# Python TCP SYN Scanner Using Scapy

## 1. Project Overview

This project involved developing a TCP SYN port scanner using Python and Scapy to explore how network scanning tools identify open and closed ports.

The scanner constructs TCP SYN packets, analyses network responses, and records the results. It was developed and tested in an authorised, isolated laboratory environment.

## 2. Objectives

- Develop a TCP SYN scanner using Python and Scapy.
- Identify TCP port states by analysing packet responses.
- Implement scope validation and scanning limits.
- Compare scanning results with Nmap.
- Evaluate a performance optimisation through controlled experiments.

## 3. Tools and Environment

| Component | Description |
|---|---|
| Programming Language | Python |
| Packet Manipulation | Scapy |
| Reference Scanner | Nmap |
| Packet Analysis | tcpdump / PCAP |
| Test Environment | Isolated Docker laboratory |
| Testing | Python unittest |

## 4. Scanner Features

The scanner implements the following functionality:

- **TCP SYN Scanning:** Sends TCP SYN packets to selected ports.
- **Response Analysis:** Identifies open ports through SYN/ACK responses and closed ports through RST/ACK responses.
- **ICMP Handling:** Records relevant ICMP unreachable responses.
- **Scope Validation:** Restricts scanning to authorised targets and ports.
- **Rate Limiting:** Controls packet transmission rates.
- **Dry-Run Mode:** Validates the scanning plan without sending packets.
- **JSON Output:** Saves structured scanning results.
- **Response Grace:** Optionally reduces waiting time after receiving a matched TCP response.

## 5. Methodology

### Step 1 — Scanner Development

Developed the scanner using Python and Scapy, separating scope validation, packet construction, response matching, and scan execution into individual modules.

### Step 2 — Scope and Safety Controls

Implemented validation to ensure scanning remained within the authorised laboratory scope and configured limits.

### Step 3 — Network Scanning

Executed the scanner against the laboratory target to identify TCP port states.

### Step 4 — Result Validation

Performed an Nmap TCP SYN scan against the same target and ports to compare the results.

### Step 5 — Performance Evaluation

Evaluated an optional response-grace mechanism designed to reduce unnecessary waiting after receiving a TCP response.

## 6. Results

The scanner successfully identified four open TCP ports in the laboratory experiment.

| TCP Port | Scapy Scanner | Nmap |
|---|---|---|
| 22 | Open | Open |
| 80 | Open | Open |
| 443 | Open | Open |
| 8080 | Open | Open |

The results matched Nmap's observations for all four tested ports.

### Performance Evaluation

Three paired trials compared the baseline scanner with the optional response-grace mechanism.

| Measurement | Baseline | Response Grace |
|---|---|---|
| Median scan duration | 6.071 seconds | 0.469 seconds |
| Open ports identified | 4 | 4 |

The response-grace mechanism reduced median scan duration by approximately **92.28%** in these trials.

However, the shorter observation window may miss delayed or conflicting responses. The experiment therefore does not establish equivalent accuracy under all network conditions.

## 7. Testing and Evidence

The project includes:

- Automated unit tests for scanner functionality.
- JSON scanning results.
- Packet capture files for network traffic analysis.
- Nmap XML output for result comparison.
- Repeated measurements for the performance experiment.

The assignment's 64 automated tests passed in the laboratory environment.

## 8. Challenges and Lessons Learned

Developing the scanner helped me understand how TCP SYN scanning works at the packet level, particularly how responses are matched to transmitted probes.

The project also highlighted the importance of controlling scanning scope, handling unexpected network responses, and validating results against an established tool.

Evaluating the response-grace mechanism demonstrated that improving scanning speed can introduce trade-offs in the completeness of collected evidence.

## 9. Future Improvements

- Implement a bounded multi-probe scheduling mechanism.
- Improve handling of delayed and out-of-order responses.
- Expand testing under different network conditions.
- Continue improving scanning efficiency while maintaining scope and rate limits.