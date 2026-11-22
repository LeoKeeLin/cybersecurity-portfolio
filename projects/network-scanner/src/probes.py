"""Pure packet construction and interpretation; nothing is transmitted here.

The scanner runner owns interface selection, local source-address discovery,
rate/retry scheduling, timeouts and duplicate aggregation.
"""

from ipaddress import IPv4Address

from scapy.layers.inet import ICMP, IP, TCP

from scope import validate_scope


SEQUENCE_MODULUS = 2 ** 32
# TCP sequence/acknowledgement numbers wrap around after the largest 32-bit value.


def build_syn(scope, source_ip, source_port, destination_port, sequence):
    """Build one authorised SYN using the runner's actual local address."""
    validate_scope(scope)
    if destination_port not in scope["ports"] or type(destination_port) is not int:
        raise ValueError("Destination port is outside the scope")
    if type(source_port) is not int or not 1 <= source_port <= 65535:
        raise ValueError("Source port must be an integer from 1 to 65535")
    if type(sequence) is not int or not 0 <= sequence < SEQUENCE_MODULUS:
        raise ValueError("Sequence must be an unsigned 32-bit integer")
    source = IPv4Address(source_ip)
    # The runner supplies the actual interface address; this helper's format
    # checks alone cannot establish that an address belongs to the workstation.
    if source.is_unspecified or source.is_multicast or source.is_loopback:
        raise ValueError("Source must be the actual unicast IPv4 address of the lab interface")
    # Scapy's / layers TCP over IP. It constructs an object; it does not send it.
    return IP(src=str(source), dst=scope["target"]) / TCP(
        sport=source_port, dport=destination_port, seq=sequence, flags="S"
    )


def _unfragmented(packet):
    """Accept only whole IPv4 packets; fragment reassembly is not supported.

    Offset zero alone is insufficient: the first fragment also has offset zero,
    but its More Fragments (MF) flag is set.
    """
    return int(packet.frag) == 0 and not (int(packet.flags) & 1)


def interpret_response(probe, response):
    """Return a matching observation dictionary, or None for unrelated traffic.

    Missing input is not a timeout verdict. The runner decides unresolved
    states after its bounded attempts. This function is stateless: a duplicate
    packet produces the same observation and must be deduplicated by the runner.
    """
    if response is None:
        return None
    sent_ip = probe.getlayer(IP)
    received_ip = response.getlayer(IP)
    if sent_ip is None or received_ip is None:
        return None
    sent_tcp = sent_ip.payload
    if not isinstance(sent_tcp, TCP) or not _unfragmented(received_ip):
        return None
    if received_ip.dst != sent_ip.src:
        return None

    payload = received_ip.payload
    if isinstance(payload, TCP):
        # Reply addresses/ports reverse the sent tuple. SYN consumes one
        # sequence number, so a valid acknowledgement is sent sequence + 1.
        if (received_ip.src != sent_ip.dst
                or payload.sport != sent_tcp.dport
                or payload.dport != sent_tcp.sport
                or payload.ack != (sent_tcp.seq + 1) % SEQUENCE_MODULUS):
            return None
        # 0x3F keeps FIN/SYN/RST/PSH/ACK/URG and ignores higher bits, including
        # ECN's ECE/CWR. 0x12 = SYN(0x02) | ACK(0x10); 0x14 = RST | ACK.
        # Exact masked values reject extra lower flags such as SYN+ACK+RST.
        flags = int(payload.flags)
        if flags & 0x3F == 0x12:  # SYN + ACK
            return {"kind": "open", "tcp_flags": flags}
        if flags & 0x3F == 0x14:  # RST + ACK in response to our SYN
            return {"kind": "closed", "tcp_flags": flags}
        return None

    if isinstance(payload, ICMP) and payload.type == 3:
        # An intermediate router may send ICMP; match the quoted probe rather
        # than requiring the outer sender to equal the target.
        quoted_ip = payload.payload
        if not isinstance(quoted_ip, IP) or not _unfragmented(quoted_ip):
            return None
        quoted_tcp = quoted_ip.payload
        # A minimum ICMP quote includes only 8 TCP bytes: both ports and seq.
        # Do not require a full TCP header, flags or acknowledgement in it.
        if (quoted_ip.proto != 6 or not isinstance(quoted_tcp, TCP)
                or quoted_ip.src != sent_ip.src or quoted_ip.dst != sent_ip.dst
                or quoted_tcp.sport != sent_tcp.sport
                or quoted_tcp.dport != sent_tcp.dport
                or quoted_tcp.seq != sent_tcp.seq):
            return None
        return {
            "kind": "icmp-unreachable",
            "icmp_type": int(payload.type),
            "icmp_code": int(payload.code),
            "responder": received_ip.src,
        }
    return None


def build_reset(probe, response):
    """Construct RST cleanup only for a matched SYN/ACK; do not send it."""
    observation = interpret_response(probe, response)
    if observation is None or observation["kind"] != "open":
        raise ValueError("RST cleanup requires a matching SYN/ACK")
    sent_ip = probe.getlayer(IP)
    sent_tcp = sent_ip.payload
    received_tcp = response.getlayer(IP).payload
    # Reset sequence uses the server's acknowledgement (our SYN sequence + 1),
    # not the server's own independent sequence number. RST is not a full ACK
    # handshake: it terminates this half-open exchange instead.
    return IP(src=sent_ip.src, dst=sent_ip.dst) / TCP(
        sport=sent_tcp.sport, dport=sent_tcp.dport,
        seq=received_tcp.ack, flags="R",
    )
