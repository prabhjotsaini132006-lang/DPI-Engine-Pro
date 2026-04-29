# DPI-Engine-Pro

<div align="center">

**I built a network traffic classifier from scratch in C++.**
**No ML libraries. No packet capture libraries. Just raw C++17.**

![Build](https://github.com/prabhjotsaini132006-lang/DPI-Engine-Pro/actions/workflows/build.yml/badge.svg)
![C++17](https://img.shields.io/badge/C%2B%2B-17-blue)
![Accuracy](https://img.shields.io/badge/ML%20Accuracy-96.30%25-brightgreen)
![Tests](https://img.shields.io/badge/Tests-117%20passing-brightgreen)
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
192.168.1.100:54552 -> 142.250.185.206:443 | YOUTUBE [SNI:www.youtube.com] TCP TLS
192.168.1.100:58747 -> 157.240.1.174:443   | FACEBOOK [SNI:www.instagram.com] TCP TLS
192.168.1.100:49582 -> 35.186.224.25:443   | ZOOM [SNI:zoom.us] TCP TLS
192.168.1.100:50684 -> 23.52.167.61:443    | NETFLIX [SNI:www.netflix.com] TCP TLS
[ALERT][14:23:04] DNS_TUNNELING
Possible DNS tunneling: 52840 bytes in DNS flow from 10.0.0.3
Severity: 85%

---

## The numbers

| What | How much |
|---|---|
| ML accuracy | **96.30%** |
| Throughput | **13,745 packets/sec** |
| Avg latency per packet | **1.46 microseconds** |
| TCP reassembly rate | **100%** |
| Unit tests | **117 passing, 0 failing** |
| Lines of C++ | **5,000+** |
| External ML libraries used | **0** |
| External packet libraries used | **0** |

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
  interface using raw sockets

---

## The ML is real

The confidence score shown next to each classification
comes from the leaf node class distribution of the
Random Forest — if a leaf node saw 9 YouTube flows
and 1 other during training, the confidence for
YouTube at that leaf is 0.9.

Feature importance is computed by permutation —
each feature is shuffled and accuracy drop measured.
The features that matter most:
=== Feature Importance Report ===
Feature  Importance  Bar
       total_bytes      28.7%  ##############
   packets_per_sec      23.5%  ###########
 avg_inter_arrival      20.3%  ##########
   avg_packet_size      14.3%  #######
     total_packets      13.2%  ######


Packet volume, transmission rate and inter-arrival time
are what distinguish YouTube from Zoom from WhatsApp —
not the domain name.

---

## Live capture

```bash
# Windows (run as Administrator)
./dpi_engine_pro --live --interface "192.168.1.x" --verbose

# Linux (run as root)
sudo ./dpi_engine_pro --live --interface eth0 --verbose
```

Output as packets arrive:
192.168.1.100:54552 -> 142.250.185.206:443 | YOUTUBE [SNI:www.youtube.com] TCP TLS
192.168.1.100:55178 -> 8.8.8.8:53          | DNS [ML] UDP
192.168.1.100:49582 -> 35.186.224.25:443   | ZOOM [SNI:zoom.us] TCP TLS

The `[SNI:domain]` tag means it was classified by reading
the TLS handshake. The `[ML]` tag means the domain was
not visible and the Random Forest classified it from
behavioral features alone.

---

## Anomaly detection
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

---

## TCP Stream Reassembly

Network packets arrive out of order.
Real DPI tools put them back in order before inspecting.
=== TCP Stream Reassembly Stats ===
Active streams:     15
Segments received:  15
Bytes received:     1241
Bytes reassembled:  1241
Out-of-order held:  0
Duplicate drops:    0
Reassembly rate:    100.0%

---

## ML Evaluation

```bash
./dpi_engine_pro --evaluate
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
=== Confusion Matrix ===
HTTP  HTTPS    DNS  YOUTUBE   ZOOM  WHATSAPP  GAMING
    HTTP         4      0      0        0      0         0       0
   HTTPS         0      4      0        0      0         0       0
     DNS         0      0      7        0      0         0       0
 YOUTUBE         0      0      0        6      0         0       0
    ZOOM         0      0      0        0      6         0       0
WHATSAPP         0      0      0        0      0         4       0
  GAMING         0      0      0        0      0         0       7

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

---

## Architecture
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
│                 │  extracts domain name
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
(exact)    (96.30% acc)
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
│                 │  BLOCK_PORT 4444
└────────┬────────┘
|
v
Final Report
throughput / latency /
classifications / alerts

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

## Blocking Rules
data/rules.txt
BLOCK_APP    GAMING     # block all gaming traffic
BLOCK_DOMAIN torrent    # block torrent domains
BLOCK_PORT   4444       # block Metasploit port
BLOCK_APP    YOUTUBE    # uncomment to block YouTube
BLOCK_IP     192.168.1.100  # block specific IP

---

## Training Data

```csv
total_packets,total_bytes,avg_packet_size,...,label
47,185000,3936,1400,800,2500,18,74000,53,443,6,1,YOUTUBE
2,100,50,60,40,5,400,20000,2,53,17,0,DNS
```

274 labeled flows across 11 app classes.
Add more rows for better accuracy.
Use CICFlowMeter or CICIDS2017 for real labeled data.

---

## License

MIT — use it, fork it, learn from it.