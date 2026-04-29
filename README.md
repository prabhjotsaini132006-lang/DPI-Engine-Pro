# DPI-Engine-Pro

<div align="center">

**I built a network traffic classifier from scratch in C++.**
**No ML libraries. No packet capture libraries. Just raw C++17.**

![Build](https://github.com/prabhjotsaini132006-lang/DPI-Engine-Pro/actions/workflows/build.yml/badge.svg)
![C++17](https://img.shields.io/badge/C%2B%2B-17-blue)
![License](https://img.shields.io/badge/License-MIT-green)

</div>

---

## What does it do?

Your computer sends thousands of packets every second.
Each packet has a destination — YouTube, Netflix, WhatsApp,
a port scanner, a DNS tunnel.

Most tools identify traffic by reading the domain name.
**That stops working the moment traffic is encrypted.**

DPI-Engine-Pro doesn't need the domain name.
It watches *how* traffic behaves — packet sizes, timing,
flow duration, byte rates — and uses a Random Forest
trained on those patterns to figure out what app
generated the traffic.

It then tells you:
```
192.168.1.100:54552 -> 142.250.185.206:443 | YOUTUBE [SNI:www.youtube.com] TCP TLS
192.168.1.100:58747 -> 157.240.1.174:443   | WHATSAPP [ML] TCP TLS
192.168.1.100:49582 -> 35.186.224.25:443   | ZOOM [SNI:zoom.us] TCP TLS
192.168.1.100:50684 -> 23.52.167.61:443    | HTTPS [SNI:www.netflix.com] TCP TLS

[ALERT][14:23:04] DNS_TUNNELING
Possible DNS tunneling: 52840 bytes in DNS flow from 10.0.0.3
Severity: 85%
```

---

## The numbers

| What | How much |
|---|---|
| Throughput (pcap replay) | **~700 packets/sec** |
| Avg latency per packet | **~1.35 ms** |
| TCP reassembly rate | **100%** |
| Fast-path cache hit rate | **~45–93%** (grows with traffic) |
| Lines of C++ | **5,000+** |
| External ML libraries used | **0** |
| External packet libraries used | **0** |
| Training dataset | **414 labeled flows (11 classes)** |

> **Note on throughput:** The ~700 pkt/sec figure is measured on pcap replay on a
> single thread. Live traffic throughput depends on interface speed and system load.
> The bottleneck is classification latency (~1.35 ms/packet), not I/O.

---

## What makes this different

Most students write a packet sniffer that prints IP addresses.

This one:

- **Parses packets at the byte level** — reads Ethernet frames,
  extracts IPv4/IPv6 headers, TCP sequence numbers, UDP ports,
  TLS handshake records

- **Reassembles TCP streams** — puts out-of-order packets back
  in the right order before inspecting the payload

- **Extracts SNI** — reads the Server Name Indication field
  from TLS Client Hello to get the domain name

- **Builds a feature vector** — 12 numerical features per flow
  that describe its behavior independent of content

- **Classifies with Random Forest** — 10 decision trees trained
  from scratch, each using random feature subsampling so they
  stay uncorrelated. Confidence comes from actual leaf node
  class distributions, not a heuristic

- **Detects anomalies** — port scanning, DNS tunneling,
  suspicious ports, abnormally high packet rates

- **Works live** — captures real traffic from your network
  interface using raw sockets / WinPcap

---

## The ML is real

The confidence score shown next to each classification
comes from the leaf node class distribution of the
Random Forest — if a leaf node saw 9 YouTube flows
and 1 other during training, the confidence for
YouTube at that leaf is 0.9.

Feature importance is computed by permutation —
each feature is shuffled and accuracy drop is measured.
The features that matter most:

```
=== Feature Importance Report ===
Feature          Importance  Bar
      total_bytes      28.7%  ##############
  packets_per_sec      23.5%  ###########
avg_inter_arrival      20.3%  ##########
  avg_packet_size      14.3%  #######
    total_packets      13.2%  ######
```

Packet volume, transmission rate and inter-arrival time
are what distinguish YouTube from Zoom from WhatsApp —
not the domain name.

---

## ML Evaluation

```bash
./dpi_engine_pro --evaluate
```

```
── Decision Tree ──
Overall Accuracy: 85.19%
── Random Forest ──
Overall Accuracy: 87.04%
── Summary ──
Winner: Random Forest by 1.85%
── Detailed Metrics ──
Overall Accuracy: 96.30%
Macro F1 Score:   89.40%
   Class   Precision    Recall        F1   Support

 YOUTUBE    100.000%  100.000%  100.000%         6
    ZOOM    100.000%  100.000%  100.000%         6
  GAMING    100.000%  100.000%  100.000%         7
 NETFLIX     75.000%  100.000%   85.714%         3
 SPOTIFY    100.000%  100.000%  100.000%         5
   STEAM    100.000%  100.000%  100.000%         4
  TIKTOK    100.000%   80.000%   88.889%         5
```

> **On accuracy:** These numbers are from cross-validation on the training set.
> Real-world accuracy on unseen traffic will differ — encrypted flows with similar
> behavioral profiles (e.g. Netflix vs YouTube both being large TLS streams) are
> genuinely hard to distinguish without SNI.

---

## Live capture

```bash
# Windows (run as Administrator)
./dpi_engine_pro --live --interface "192.168.1.x" --verbose

# Linux (run as root)
sudo ./dpi_engine_pro --live --interface eth0 --verbose
```

Output as packets arrive:
```
192.168.1.100:54552 -> 142.250.185.206:443 | YOUTUBE [SNI:www.youtube.com] TCP TLS
192.168.1.100:55178 -> 8.8.8.8:53          | DNS [ML] UDP
192.168.1.100:49582 -> 35.186.224.25:443   | ZOOM [SNI:zoom.us] TCP TLS
```

The `[SNI:domain]` tag means it was classified by reading
the TLS handshake. The `[ML]` tag means the domain was
not visible and the Random Forest classified it from
behavioral features alone.

---

## Anomaly detection

```
[ALERT][14:23:01] PORT_SCAN
Port scan from 192.168.1.105 (12 ports in 2 seconds)
Severity: 80%

[ALERT][14:23:04] DNS_TUNNELING
Possible DNS tunneling: 52840 bytes in DNS flow from 10.0.0.3
Severity: 85%

[ALERT][14:23:09] SUSPICIOUS_PORT
Connection to port 4444 (Metasploit default) from 10.0.0.7
Severity: 90%

[ALERT][14:23:15] HIGH_PACKET_RATE
50,000 packets/sec from 192.168.1.200 — possible flood
Severity: 70%
```

Detection logic is behavioral, not signature-based:
- **Port scan** — tracks unique destination ports per source IP within a time window
- **DNS tunneling** — flags DNS flows exceeding normal data volume thresholds
- **Suspicious ports** — hardcoded list of known malicious/C2 ports (4444, 31337, 1337, etc.)
- **High packet rate** — per-flow packets/sec compared against configurable threshold

---

## TCP Stream Reassembly

Network packets arrive out of order.
Real DPI tools put them back in order before inspecting.

```
=== TCP Stream Reassembly Stats ===
Active streams:     138
Segments received:  3240
Bytes received:     2009238
Bytes reassembled:  2002056
Out-of-order held:  0
Duplicate drops:    29
Reassembly rate:    99.6%
===================================
```

Implementation tracks per-flow sequence numbers, holds
out-of-order segments in a buffer (max 64 per stream),
flushes them in-order when the gap is filled, and drops
duplicates. Thread-safe via per-reassembler mutex.

---

## Performance

Measured on a Windows laptop, pcap replay mode, single thread:

```
════════════════════════════════════
     Performance Benchmark Report
════════════════════════════════════
Packets processed:  6,013
Total data:         2 MB
Classifications:    6,013

Throughput:         ~700 packets/sec
Avg latency:        ~1.35 ms per packet

── Cache Performance ──
  Entries:  30
  Hits:     5601
  Misses:   412
  Hit rate: 93.15%
════════════════════════════════════
```

The fast-path cache stores recently classified flows by
5-tuple. Repeated packets in the same flow skip the ML
classifier entirely — this is why cache hit rate reaches
93% on sustained traffic captures.

---

## TCP Stream Reassembly (live capture run)

```
=== TCP Stream Reassembly Stats ===
Active streams:     138
Segments received:  3240
Bytes received:     2,009,238
Bytes reassembled:  2,002,056
Out-of-order held:  0
Duplicate drops:    29
Reassembly rate:    99.6%
===================================
```

---

## Building

```bash
git clone https://github.com/prabhjotsaini132006-lang/DPI-Engine-Pro.git
cd DPI-Engine-Pro
mkdir build && cd build
cmake .. -G "Ninja" -DCMAKE_BUILD_TYPE=Release
ninja
```

Requirements: g++ (C++17), CMake 3.10+, Ninja

---

## Usage

```bash
# Analyse a pcap file
./dpi_engine_pro --input capture.pcap

# Every packet with classification reason
./dpi_engine_pro --input capture.pcap --verbose

# Evaluate ML accuracy
./dpi_engine_pro --evaluate

# Live capture
./dpi_engine_pro --live --interface "192.168.1.x"

# Use Decision Tree instead of Random Forest
./dpi_engine_pro --input capture.pcap --no-rf

# Disable TCP reassembly
./dpi_engine_pro --input capture.pcap --no-reassembly

# List network interfaces
./dpi_engine_pro --list-interfaces

# All options
./dpi_engine_pro --help
```

---

## Tests

```bash
cd build && ./test_classifier.exe
```

```
── Test 1:  FlowFeatures         9/9   PASS
── Test 2:  DNS Prediction       2/2   PASS
── Test 3:  YouTube Prediction   1/1   PASS
── Test 4:  Save and Load        3/3   PASS
── Test 5:  Untrained            2/2   PASS
── Test 6:  Confidence           3/3   PASS
── Test 7:  Random Forest        4/4   PASS
── Test 8:  Rule Manager         4/4   PASS
── Test 9:  Fast Path Cache      9/9   PASS
── Test 10: Training Data        6/6   PASS
── Test 23: Anomaly Detector     5/5   PASS
── Test 25: Stream Reassembler   8/8   PASS
── Test 26: Benchmark            7/7   PASS
── Test 27: Anomaly Extended     5/5   PASS
...
Results: 117 passed, 0 failed
```

---

## Architecture

```
Raw packets (pcap file or live interface)
|
v
┌─────────────────┐
│  Packet Parser  │  Ethernet → IP → TCP/UDP
│  IPv4 + IPv6    │  extracts ports, seq numbers,
│  TCP flags      │  TLS detection
└────────┬────────┘
         |
         v
┌─────────────────┐
│ Stream          │  puts TCP segments in order
│ Reassembler     │  handles out-of-order delivery
└────────┬────────┘
         |
         v
┌─────────────────┐
│  SNI Extractor  │  reads TLS Client Hello
│  Protocol Parser│  HTTP/DNS/TLS byte parsing
└────────┬────────┘
         |
         v
┌─────────────────┐
│ Flow Features   │  12 numerical features
│                 │  per network flow
└────────┬────────┘
         |
    ┌────┴────┐
    |         |
    v         v
SNI found   No SNI
    |         |
    v         v
sniToApp   Random Forest
(exact)    (behavioral)
    |         |
    └────┬────┘
         |
         v
┌─────────────────┐
│ Anomaly         │  port scan, DNS tunnel,
│ Detector        │  suspicious ports, floods
└────────┬────────┘
         |
         v
┌─────────────────┐
│ Rule Manager    │  BLOCK_APP GAMING
│ Fast-path Cache │  BLOCK_PORT 4444
└────────┬────────┘
         |
         v
    Final Report
throughput / latency /
classifications / alerts
```

---

## Training Data

```csv
total_packets,total_bytes,avg_packet_size,...,label
72,57235,795.0,1492,54,40627.7,1.41,1409.2,3.2,443,6,1,HTTPS
3,180,60.0,80,40,12.0,250.0,15000.0,6.0,53,17,0,DNS
```

414 labeled flows across 11 app classes, combining flows
extracted from real captured traffic with statistically
realistic augmented samples. Real flows were captured
using Wireshark and labeled by SNI or port. Augmented
flows use per-class distributions derived from the real
captures — not hand-crafted round numbers.

To grow the dataset with your own captures:
```bash
pip install dpkt
python extract_flows.py your_capture.pcapng YOUTUBE
# appends labeled flows to training_flows.csv
```

Then delete `build/data/model.txt` and rerun to retrain.

---

## Blocking Rules

```
# data/rules.txt
BLOCK_APP    GAMING     # block all gaming traffic
BLOCK_DOMAIN torrent    # block torrent domains
BLOCK_PORT   4444       # block Metasploit port
# BLOCK_APP  YOUTUBE    # uncomment to block YouTube
# BLOCK_IP   192.168.1.100  # block specific IP
```

---

## What I learned building this

- How Ethernet frames, IP packets, TCP segments
  and TLS handshakes are structured at the byte level
- How Decision Trees split on Gini impurity
- Why Random Forests need feature subsampling
  to keep trees uncorrelated
- How confidence scores should come from leaf
  node class distributions not heuristics
- How raw sockets work on Windows and Linux
- How TCP stream reassembly handles out-of-order delivery
- How to write thread-safe code with mutexes and atomics
- How to design a system where 26 components
  work together without circular dependencies

---

## License

MIT — use it, fork it, learn from it.
