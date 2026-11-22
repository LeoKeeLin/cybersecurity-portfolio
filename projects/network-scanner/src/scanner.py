"""Bounded sequential scanning with an injectable transport for offline tests."""

from datetime import datetime, timezone
import queue
import secrets
import threading
import time

import scapy
from scapy.all import AsyncSniffer, conf, get_if_addr, get_if_list
from scapy.layers.inet import IP

from probes import build_reset, build_syn, interpret_response
from scope import validate_response_grace, validate_scope


class ScanError(RuntimeError):
    """Execution failed; do not present the run as a complete measurement."""


def utc_now():
    # Wall-clock UTC is for experiment provenance. Duration/deadline arithmetic
    # below uses monotonic time, which does not jump if the system clock changes.
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


class LiveTransport:
    """Capture before sending and constrain the sending socket to the scope interface."""

    def __init__(self, scope):
        self.scope = scope
        self.socket = None
        self.sniffer = None
        self.packets = queue.Queue(maxsize=10000)
        # The capture thread hands observations to the main scanning thread.
        # Bounded memory + explicit overflow failure avoid silent evidence loss.
        self.overflow = False

    def __enter__(self):
        # Python calls this on entering "with LiveTransport(...)". Startup must
        # succeed before the runner can transmit its first probe.
        try:
            interface = self.scope["interface"]
            if interface not in get_if_list():
                raise ScanError(f"Interface {interface!r} does not exist")
            self.source_ip = get_if_addr(interface)
            # Scapy's L3 sender also consults routes. Reject a different default
            # route/interface instead of assuming the socket alone pins traffic.
            route_interface, route_source, _ = conf.route.route(
                self.scope["target"]
            )
            if (str(route_interface) != interface or route_source != self.source_ip
                    or self.source_ip == "0.0.0.0"):
                raise ScanError("No matching IPv4 route/source address on the scope interface")
            self.socket = conf.L3socket(iface=interface, promisc=False)
            ready = threading.Event()

            def receive_packet(packet):
                try:
                    # Timestamp immediately in the callback, before queueing.
                    # This reduces timing distortion from later processing waits.
                    self.packets.put_nowait((packet, time.monotonic()))
                except queue.Full:
                    self.overflow = True

            self.sniffer = AsyncSniffer(
                iface=interface, promisc=False, store=False, prn=receive_packet,
                filter=f"ip dst host {self.source_ip} and (tcp or icmp)",
                started_callback=ready.set,
            )
            # This in-memory receiver is separate from the supplied tcpdump
            # capture helper; it does not itself create the submitted PCAP.
            self.sniffer.start()
            if not ready.wait(3):
                reason = getattr(self.sniffer, "exception", None)
                raise ScanError(f"Capture did not become ready: {reason or 'startup timeout'}")
            return self
        except Exception as error:
            self.__exit__(None, None, None)
            raise ScanError(f"Cannot initialise scan transport: {error}") from error

    def send(self, packet):
        try:
            self._check_capture()
            if str(packet.route()[0]) != self.scope["interface"]:
                raise ScanError("Packet route no longer matches the authorised interface")
            self.socket.send(packet)
        except Exception as error:
            raise ScanError(f"Packet transmission failed: {error}") from error

    def _check_capture(self):
        if self.overflow:
            raise ScanError("Receive queue overflowed; measurement would be incomplete")
        if self.sniffer is not None and not self.sniffer.running:
            raise ScanError(f"Capture stopped unexpectedly: {self.sniffer.exception}")

    def receive(self, timeout):
        self._check_capture()
        try:
            if timeout <= 0:
                # Final drain: consume already queued packets without waiting.
                return self.packets.get_nowait()
            return self.packets.get(timeout=timeout)
        except queue.Empty:
            self._check_capture()
            return None

    def __exit__(self, *unused):
        # Context-manager cleanup runs on normal completion and exceptions.
        try:
            if self.sniffer is not None:
                if self.sniffer.running and hasattr(self.sniffer, "stop_cb"):
                    self.sniffer.stop()
                elif getattr(self.sniffer, "thread", None) is not None:
                    self.sniffer.join(timeout=1)
        finally:
            if self.socket is not None:
                self.socket.close()


def run_scan(scope, tool_version, *, transport_factory=LiveTransport,
             clock=time.monotonic, sleep=time.sleep, utc=utc_now, identifiers=None,
             response_grace=None):
    """Perform bounded attempts. Inject fake I/O and clocks for non-network tests.

    Each attempt gets a distinct source port/sequence pair. Earlier attempts
    remain matchable while the run continues, so late replies are not assigned
    to the wrong retry. All transmitted SYNs and cleanup RSTs share a limiter.
    """
    validate_scope(scope)
    validate_response_grace(response_grace, scope["timeout_seconds"])
    started_utc = utc()
    started = clock()
    base_port = 32768 + secrets.randbelow(28000)
    # Each attempt increments the source port, so at most 30*2 attempts remain
    # distinct and below 65536. These are TCP header values, not bound sockets;
    # the OS can independently send resets to SYN/ACKs received on these ports.
    if identifiers is None:
        identifiers = lambda index: (base_port + index, secrets.randbits(32))
    interval = 1 / scope["maximum_rate_pps"]
    # At 20 packets/second, application transmissions are spaced >= 0.05 s.
    next_send = clock()
    # Counts cover our sends, not kernel-generated resets or every PCAP frame.
    counters = {"syn_sent": 0, "rst_sent": 0, "unmatched_packets": 0}
    records = {
        port: {"port": port, "state": "filtered-or-no-response", "attempts": [],
               "observations": [], "conflicting_tcp_states": False}
        for port in sorted(scope["ports"])
    }
    sent = []
    seen = {}
    # sent retains all attempt identities for late matching. seen links each
    # exact response fingerprint to its stored observation for duplicate counts.

    try:
        with transport_factory(scope) as transport:
            source_ip = transport.source_ip

            def send_limited(packet):
                nonlocal next_send
                # One limiter for both probe SYNs and cleanup RSTs; sending a
                # cleanup cannot bypass the configured application rate limit.
                delay = next_send - clock()
                if delay > 0:
                    sleep(delay)
                sent_at = clock()
                transport.send(packet)
                # Spacing is measured after send completes, conservatively
                # including time spent resolving link-layer delivery.
                next_send = clock() + interval
                return sent_at

            def process(item):
                response, received_at = item
                # Try all sent probes, not just the latest one. A late reply to
                # attempt 1 must not be mislabelled as a response to attempt 2.
                for probe, attempt, record in sent:
                    if received_at < attempt["sent_elapsed_seconds"] + started:
                        continue
                    observation = interpret_response(probe, response)
                    if observation is None:
                        continue
                    attempt["matched_responses"] += 1
                    fingerprint = (attempt["source_port"], bytes(response.getlayer(IP)))
                    # Exact IP bytes define duplication here. A changed packet
                    # (e.g. different TCP sequence or IP header) is retained as
                    # another observation, even when it has the same port state.
                    elapsed = round(received_at - started, 6)
                    if fingerprint in seen:
                        previous = seen[fingerprint]
                        previous["count"] += 1
                        previous["last_elapsed_seconds"] = elapsed
                        return record["port"], observation["kind"], received_at
                    observation.update({
                        "attempt": attempt["number"], "count": 1,
                        "first_elapsed_seconds": elapsed, "last_elapsed_seconds": elapsed,
                        "response_seconds": round(max(
                            0, received_at - started - attempt["sent_elapsed_seconds"]
                        ), 6),
                    })
                    record["observations"].append(observation)
                    seen[fingerprint] = observation
                    kinds = {entry["kind"] for entry in record["observations"]}
                    record["conflicting_tcp_states"] = "open" in kinds and "closed" in kinds
                    # Retain contradictory evidence and flag it. An observed
                    # SYN/ACK is stronger evidence of openness than silence.
                    if "open" in kinds:
                        record["state"] = "open"
                    elif "closed" in kinds:
                        record["state"] = "closed"
                    if observation["kind"] == "open":
                        send_limited(build_reset(probe, response))
                        counters["rst_sent"] += 1
                    return record["port"], observation["kind"], received_at
                counters["unmatched_packets"] += 1

            for port, record in records.items():
                # Sequential baseline: finish this port's observation window
                # before starting the next. Resolved ports need no retry.
                for number in range(1, scope["maximum_attempts"] + 1):
                    if record["state"] in ("open", "closed"):
                        break
                    source_port, sequence = identifiers(len(sent))
                    probe = build_syn(scope, source_ip, source_port, port, sequence)
                    # Register before sending so an immediate reply can match.
                    attempt = {"number": number, "source_port": source_port,
                               "sequence": sequence, "matched_responses": 0}
                    record["attempts"].append(attempt)
                    sent.append((probe, attempt, record))
                    sent_at = send_limited(probe)
                    attempt["sent_elapsed_seconds"] = sent_at - started
                    counters["syn_sent"] += 1
                    deadline = clock() + scope["timeout_seconds"]
                    grace_started = False
                    # Baseline: retain the full window. Extension: shorten it
                    # only on this port's first matched TCP verdict. ICMP,
                    # unrelated packets and duplicates never restart the grace.
                    while clock() < deadline:
                        item = transport.receive(deadline - clock())
                        if item is not None:
                            match = process(item)
                            if (response_grace is not None and not grace_started
                                    and match is not None and match[0] == port
                                    and match[1] in ("open", "closed")):
                                deadline = min(deadline, match[2] + response_grace)
                                # match[2] is capture time, not processing time.
                                # Later duplicates cannot keep extending the run.
                                grace_started = True
                    attempt["window_ended_elapsed_seconds"] = round(clock() - started, 6)
                    # Actual end can exceed the nominal deadline if rate-limited
                    # RST cleanup or packet processing occupied the main thread.
                    attempt["response_grace_triggered"] = grace_started
                # Later ports' windows also collect replies to earlier probes.

            # Drain already captured responses, without extending the window.
            for _ in range(10000):
                item = transport.receive(0)
                if item is None:
                    break
                process(item)
            else:
                raise ScanError("Receive backlog did not drain within its bound")
    except ScanError:
        raise
    except Exception as error:
        raise ScanError(f"Scan execution failed: {error}") from error

    # Only successful transport cleanup reaches this complete-result builder.
    # ICMP-only/silent ports retain their initial unresolved summary, with any
    # ICMP evidence preserved in observations rather than called "closed".
    ended_utc = utc()
    return {
        "schema": "wqe7002-tcp-result-v1", "mode": "execute", "status": "complete",
        "tool_version": tool_version, "scapy_version": scapy.__version__,
        "scope_id": scope["scope_id"], "option": scope["option"],
        "environment": scope["environment"], "capture_point": scope["capture_point"],
        "topology": scope["topology"], "started_utc": started_utc, "ended_utc": ended_utc,
        "elapsed_seconds": round(clock() - started, 6),
        "parameters": {"target": scope["target"], "ports": sorted(scope["ports"]),
                       "interface": scope["interface"], "source_ip": source_ip,
                       "rate_pps": scope["maximum_rate_pps"],
                       "attempts": scope["maximum_attempts"],
                       "timeout_seconds": scope["timeout_seconds"],
                       "response_grace_seconds": response_grace},
        "counts": counters, "results": list(records.values()),
        "limits": [
            "No response does not prove filtering or host absence.",
            "ICMP errors are retained; without a TCP verdict the state remains filtered-or-no-response.",
            "Response timings include capture/scheduling effects; they are not precise network RTT measurements.",
            "The OS may independently send RSTs; inspect the capture for actual wire behaviour.",
            "A shortened response grace can miss late duplicate/conflicting replies; prior probes remain matchable until the run ends.",
        ],
    }
