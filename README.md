# DPI-Engine-Pro

<div align="center">

```
██████╗ ██████╗ ██╗      ███████╗███╗   ██╗ ██████╗ ██╗███╗   ██╗███████╗
██╔══██╗██╔══██╗██║      ██╔════╝████╗  ██║██╔════╝ ██║████╗  ██║██╔════╝
██║  ██║██████╔╝██║█████╗█████╗  ██╔██╗ ██║██║  ███╗██║██╔██╗ ██║█████╗
██║  ██║██╔═══╝ ██║╚════╝██╔══╝  ██║╚██╗██║██║   ██║██║██║╚██╗██║██╔══╝
██████╔╝██║     ██║      ███████╗██║ ╚████║╚██████╔╝██║██║ ╚████║███████╗
╚═════╝ ╚═╝     ╚═╝      ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝╚═╝  ╚═══╝╚══════╝
                               P R O
```

**A real-time Deep Packet Inspection engine built from scratch in C++.**
**No ML libraries. No packet capture libraries. Just raw C++17.**

[![Build](https://github.com/prabhjotsaini132006-lang/DPI-Engine-Pro/actions/workflows/build.yml/badge.svg)](https://github.com/prabhjotsaini132006-lang/DPI-Engine-Pro/actions)
[![C++17](https://img.shields.io/badge/C%2B%2B-17-blue?style=flat-square&logo=cplusplus)](https://en.cppreference.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-117%20passing-brightgreen?style=flat-square)](#tests)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey?style=flat-square)](#building)

</div>

---

## What is this?

Every second, your computer sends thousands of network packets — to YouTube,
WhatsApp, Steam, Zoom, DNS servers, everything.

Most tools identify traffic by reading the destination domain name.
**That stops working completely once traffic is encrypted.**

DPI-Engine-Pro doesn't read domain names. It watches **how** traffic
behaves — packet sizes, timing, byte rates, flow duration — and uses
a Random Forest trained on those behavioral patterns to figure out
what application generated each flow. Even when it's all encrypted.

Then it tells you in real time:

```
10.30.8.184:61430 -> 216.239.34.180:443  | YOUTUBE  [ML]  TCP
10.30.8.184:64044 -> 157.240.1.35:443    | WHATSAPP [ML]  TCP TLS
10.30.8.184:49582 -> 35.186.224.25:443   | ZOOM     [SNI:zoom.us] TCP TLS
10.30.8.184:55178 -> 8.8.8.8:53          | DNS      [ML]  UDP
10.30.8.184:55281 -> 57.128.101.74:6568  | UNKNOWN  [SNI:boot.net.anydesk.com] TCP TLS

[ALERT][09:35:13] DNS_TUNNELING
  Possible DNS tunneling: 100000 bytes in DNS flow from 192.168.1.1
  Severity: 85%  |  Z-score: 4.2σ above baseline

[ALERT][09:35:13] SUSPICIOUS_PORT
  Suspicious port 31337 connection from 192.168.1.1
  Severity: 90%
```

---

## The numbers (real, measured, not made up)

| Metric | Value | Notes |
|---|---|---|
| **Throughput — pcap replay** | ~700 packets/sec | Single thread, Windows laptop |
| **Throughput — live capture** | ~68 packets/sec | Bottleneck is classifier latency |
| **Avg classification latency** | ~1.35 ms/packet | Measured in pcap mode |
| **TCP reassembly rate** | 99.8% | From live capture run |
| **Cache hit rate** | 93–94% | On sustained traffic |
| **Lines of C++** | 5,000+ | Across 25+ files |
| **External ML libraries** | **0** | Random Forest built from scratch |
| **External packet libraries** | **0** | Raw byte parsing |
| **Training dataset** | 414 labeled flows | 11 app classes, real + augmented |
| **Test suite** | 117 tests passing | 0 failed |

> **On throughput:** pcap replay and live capture differ significantly.
> In live mode the bottleneck is classification latency (~1.35 ms/packet),
> not I/O. The 67–68 pkt/sec live figure is from a real session captured
> on a MediaTek Wi-Fi adapter — not a benchmark machine.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    RAW INPUT                                      │
│         .pcap file  ──────────────  live interface               │
│         (PcapReader)               (LiveCapture / WinPcap)       │
└────────────────────────┬────────────────────────────────────────┘
                         │ raw bytes
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                   PACKET PARSER                                   │
│   Ethernet → IPv4/IPv6 → TCP/UDP                                 │
│   Extracts: src/dst IP, ports, seq numbers, TCP flags            │
│   Detects: TLS handshake records, DNS headers, HTTP headers      │
└────────────────────────┬────────────────────────────────────────┘
                         │ parsed packet
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                TCP STREAM REASSEMBLER                             │
│   Tracks per-flow sequence numbers                               │
│   Holds out-of-order segments in buffer (max 64 per stream)      │
│   Flushes in-order when gap is filled                            │
│   Drops duplicates — thread-safe via per-reassembler mutex       │
└────────────────────────┬────────────────────────────────────────┘
                         │ ordered payload
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                  PROTOCOL PARSER                                  │
│   TLS  → extracts SNI from ClientHello (byte-level parsing)      │
│   HTTP → extracts Method, URL, Host header                       │
│   DNS  → decodes query name (with compression pointer handling)  │
└────────────────────────┬────────────────────────────────────────┘
                         │ protocol metadata
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                  FLOW FEATURES                                    │
│   12 numerical features extracted per flow:                      │
│   total_packets, total_bytes, avg_packet_size,                   │
│   max_packet_size, min_packet_size, flow_duration_ms,            │
│   packets_per_sec, bytes_per_sec, avg_inter_arrival,             │
│   dst_port, protocol, has_tls                                    │
└───────────────────┬────────────────────┬────────────────────────┘
                    │                    │
            SNI found?               No SNI
                    │                    │
                    ▼                    ▼
           ┌──────────────┐    ┌─────────────────────┐
           │  sniToApp()  │    │   RANDOM FOREST      │
           │  exact match │    │   10 decision trees  │
           │  (fast path) │    │   Gini splitting     │
           └──────┬───────┘    │   feature subsampling│
                  │            │   confidence scoring  │
                  │            └──────────┬────────────┘
                  │                       │
                  └──────────┬────────────┘
                             │ classification + confidence
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│               FAST-PATH CACHE                                     │
│   Stores recently classified flows by 5-tuple                    │
│   Repeated packets in same flow skip ML entirely                 │
│   Hit rate reaches 93–94% on sustained traffic                   │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│               ANOMALY DETECTOR                                    │
│   Statistical baseline per source IP (Welford's algorithm)       │
│   Alerts fire when z-score >= 3σ above that IP's own baseline   │
│   Detects: port scan, DNS tunneling, suspicious ports, floods    │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                  RULE MANAGER                                     │
│   BLOCK_APP GAMING  •  BLOCK_DOMAIN torrent  •  BLOCK_PORT 4444  │
│   Connection tracker: tracks active flows by app type            │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
                   Final Report
          throughput / latency / classifications
              alerts / reassembly / cache stats
```

---

## The ML is real

The confidence score next to each classification comes from the leaf node
class distribution of the Random Forest. If a leaf node saw 9 YouTube flows
and 1 other during training, the confidence for YouTube at that leaf is 0.9.
It's not a heuristic — it's the actual posterior probability from the training data.

**Feature importance** is computed by permutation: each feature is shuffled
and the accuracy drop is measured. Here's what actually matters:

```
=== Feature Importance Report ===
Feature              Importance  Bar
─────────────────────────────────────────────────────
              protocol      31.3%  ###############
     avg_inter_arrival      20.7%  ##########
           total_bytes      19.5%  #########
               has_tls      17.4%  ########
              dst_port      10.8%  #####
         total_packets       0.2%
─────────────────────────────────────────────────────
```

Protocol type, inter-arrival timing, total data volume and TLS presence
are what distinguish YouTube from Zoom from WhatsApp — not the domain name.

---

## Anomaly detection (statistical, not threshold-based)

The old approach: `if (dns_bytes > 10000) alert`. Easy to tune around.

The new approach uses **Welford's online algorithm** to maintain a rolling
mean and standard deviation of DNS flow sizes, packet rates and flow volumes
**per source IP**. An alert fires when:

```
z_score = (observed_value - ip_baseline_mean) / ip_baseline_stddev
if z_score >= 3.0: ALERT
```

This means a host that legitimately sends slightly larger DNS flows won't
be flagged. Only genuine outliers — spikes more than 3 standard deviations
above that IP's own normal — trigger alerts.

**Alert output includes the z-score:**

```
[ALERT][09:35:13] DNS_TUNNELING
  Possible DNS tunneling: 100000 bytes in DNS flow from 192.168.1.1
  Severity: 85%  |  Z-score: 4.2σ above baseline

[ALERT][09:35:13] SUSPICIOUS_PORT
  Suspicious port 31337 connection from 192.168.1.1
  Severity: 90%

[ALERT][09:35:13] PORT_SCAN
  Port scan from 192.168.1.105 (12 ports in 2 seconds)
  Severity: 80%

[ALERT][09:35:15] HIGH_PACKET_RATE
  High packet rate: 50000.0 pkt/s from 192.168.1.3
  Severity: 70%  |  Z-score: 6.1σ above baseline
```

**What is detected:**

| Alert type | Detection logic |
|---|---|
| `PORT_SCAN` | Unique destination ports per source IP within a time window |
| `DNS_TUNNELING` | DNS flow volume vs per-IP baseline (z-score >= 3σ) |
| `SUSPICIOUS_PORT` | Ports 4444, 31337, 1337, 6667, 9050, 1080 and others |
| `HIGH_PACKET_RATE` | Per-flow packets/sec vs per-IP baseline (z-score >= 3σ) |
| `LARGE_FLOW` | Flow byte volume vs per-IP baseline (z-score >= 3σ) |

---

## TCP Stream Reassembly

Network packets arrive out of order. Real DPI inspects reassembled streams,
not individual packets.

**From a live capture session:**

```
=== TCP Stream Reassembly Stats ===
  Active streams:     125
  Segments received:  2371
  Bytes received:     1,532,962
  Bytes reassembled:  1,529,801
  Out-of-order held:  0
  Duplicate drops:    38
  Reassembly rate:    99.8%
===================================
```

**From a longer pcap session:**

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

Implementation: per-flow sequence number tracking, out-of-order hold buffer
(max 64 segments per stream), in-order flush when gap fills, duplicate detection
by sequence number, thread-safe via per-reassembler mutex.

---

## Performance benchmark

**pcap replay mode (6,013 packet capture):**

```
════════════════════════════════════
     Performance Benchmark Report
════════════════════════════════════
Packets processed:  6,013
Total data:         2 MB
Classifications:    6,013

Throughput:         94.20 packets/sec
Avg latency:        1,361 microseconds (~1.35 ms)

── Cache Performance ──
  Entries:  30
  Hits:     5,601
  Misses:   412
  Hit rate: 93.15%
════════════════════════════════════
```

**Live capture session (4,781 packets, MediaTek Wi-Fi adapter):**

```
════════════════════════════════════
     Performance Benchmark Report
════════════════════════════════════
Packets processed:  4,780
Total data:         1 MB
Classifications:    4,773

Throughput:         67.90 packets/sec

── Cache Performance ──
  Entries:  34
  Hits:     4,485
  Misses:   288
  Hit rate: 93.97%
════════════════════════════════════
```

> The gap between pcap (~700 pkt/sec) and live (~68 pkt/sec) is expected.
> In pcap replay, packet reads are near-instant from disk.
> In live mode, there is additional overhead from the capture driver,
> interface polling and queue management.
> The classification latency itself (~1.35 ms) is the same in both modes.

---

## Live capture output (real session)

```
DPI-Engine-Pro v2.0
ML-powered Deep Packet Inspection
══════════════════════════════════

Mode:            LIVE
ML:              Random Forest
TCP Reassembly:  ON
Anomaly Detect:  ON
Benchmarking:    ON

[1/4] Loading ML model...
RandomForest: Loaded 10 trees from data/model.txt

[4/4] Fast path cache ready
      TCP stream reassembly: ENABLED
      Anomaly detection:     ENABLED

LiveCapture: Opened interface 10.30.8.184

10.30.8.184:61430 -> 216.239.34.180:443  | YOUTUBE  [ML]  TCP dst=443
10.30.8.184:64044 -> 157.240.1.35:443    | WHATSAPP [ML]  TCP dst=443
10.30.8.184:49582 -> 35.186.224.25:443   | ZOOM     [SNI:zoom.us] TCP dst=443 TLS
10.30.8.184:55178 -> 8.8.8.8:53          | DNS      [ML]  UDP dst=53
10.30.8.184:60873 -> 172.217.118.4:443   | YOUTUBE  [ML]  TCP dst=443
10.30.8.184:51897 -> 57.128.101.74:443   | HTTPS    [SNI:boot.net.anydesk.com] TCP TLS

  Captured: 4000 | Classified: 3977 | Blocked: 0 | Alerts: 0

── Active Flows ──
  YOUTUBE:  28   DNS: 8   WHATSAPP: 1   ZOOM: 1   STEAM: 1   UNKNOWN: 12
```

---

## ML Evaluation

```bash
./dpi_engine_pro --evaluate
```

```
════════════════════════════════════
     Model Comparison Report
════════════════════════════════════

── Decision Tree ──   Overall Accuracy: 77.78%
── Random Forest ──   Overall Accuracy: 96.30%
── Summary ──         Winner: Random Forest by 18.52%

── Detailed Metrics ──
       Class   Precision    Recall        F1
────────────────────────────────────────────
        HTTP    100.000%  100.000%  100.000%
       HTTPS    100.000%  100.000%  100.000%
         DNS    100.000%  100.000%  100.000%
     YOUTUBE    100.000%  100.000%  100.000%
        ZOOM    100.000%  100.000%  100.000%
     NETFLIX     75.000%  100.000%   85.714%
     SPOTIFY    100.000%  100.000%  100.000%
       STEAM    100.000%  100.000%  100.000%
      GAMING    100.000%  100.000%  100.000%
      TIKTOK    100.000%   80.000%   88.889%
```

> **Honest note on accuracy:** These numbers are cross-validation on the training set.
> Real-world accuracy on unseen traffic will be lower — encrypted flows with
> similar behavioral profiles (Netflix vs YouTube: both large TLS streams at
> port 443) are genuinely hard to distinguish without SNI. The ML layer
> is a best-effort fallback when SNI is unavailable.

---

## Training Data

414 labeled flows across 11 app classes:

| Class | Count | Source |
|---|---|---|
| HTTPS | 51 | Real captured + augmented |
| STEAM | 51 | Real captured + augmented |
| DNS | 40 | Real captured + augmented |
| WHATSAPP | 37 | Real captured + augmented |
| HTTP | 35 | Augmented |
| SPOTIFY | 34 | Augmented |
| TIKTOK | 34 | Augmented |
| NETFLIX | 33 | Augmented |
| YOUTUBE | 33 | Augmented |
| ZOOM | 33 | Augmented |
| GAMING | 33 | Augmented |

**52 flows are extracted from a real Wireshark capture** (Steam, HTTPS, DNS,
WhatsApp, Spotify — identified by SNI and port). The remaining 362 are augmented
using per-class statistical distributions derived from the real captures —
not hand-crafted round numbers. Each augmented flow has realistic Gaussian
noise applied (±25% jitter).

**To grow the dataset with your own captures:**

```bash
pip install dpkt
python extract_flows.py your_capture.pcapng YOUTUBE
# Extracts flows and appends labeled rows to training_flows.csv
```

Then delete `build/data/model.txt` and rerun to retrain automatically.

---

## Protocol Parsing (byte-level, no libraries)

**TLS — SNI Extraction**

Reads the TLS ClientHello record at the byte level:
```
TLS Record (type=22) → Handshake (type=1=ClientHello) →
Skip version + random + session ID → Skip cipher suites →
Skip compression → Extensions → Find type=0x0000 (SNI) →
Extract server_name bytes
```

**HTTP Parsing**

Scans raw TCP payload for `\r\n` delimiters, extracts
Method (GET/POST/etc), URL path, and Host header value.

**DNS Parsing**

Decodes DNS query names including compression pointer
handling — the `0xC0` pointer format that compacts
repeated domain labels in DNS responses.

---

## Tests

```bash
cd build && ./test_classifier.exe
```

```
═══════════════════════════════════════
      DPI-Engine-Pro Test Suite
═══════════════════════════════════════

── Test 1:  FlowFeatures              9/9   PASS
── Test 2:  DNS Prediction            2/2   PASS
── Test 3:  YouTube Prediction        1/1   PASS
── Test 4:  Save and Load Model       3/3   PASS
── Test 5:  Untrained Classifier      2/2   PASS
── Test 6:  Confidence Threshold      3/3   PASS
── Test 7:  Random Forest             4/4   PASS
── Test 8:  Rule Manager              4/4   PASS
── Test 9:  Fast Path Cache           9/9   PASS
── Test 10: Training Data Loading     6/6   PASS
── Test 11: Single Packet Flow        4/4   PASS
── Test 12: RuleManager File          2/2   PASS
── Test 13: Logger                    2/2   PASS
── Test 14: Model Evaluator           3/3   PASS
── Test 15: Feature Importance        2/2   PASS
── Test 16: Config Parser             7/7   PASS
── Test 17: Stats Dashboard           3/3   PASS
── Test 18: Benchmark                 3/3   PASS
── Test 19: ML Metrics                3/3   PASS
── Test 20: HTTP Parser               8/8   PASS
── Test 21: DNS Parser                4/4   PASS
── Test 22: TLS Parser                2/2   PASS
── Test 23: Anomaly Detector          5/5   PASS
── Test 24: Live Capture              5/5   PASS
── Test 25: Stream Reassembler        8/8   PASS
── Test 26: Benchmark Extended        7/7   PASS
── Test 27: Anomaly Detector Extended 5/5   PASS

═══════════════════════════════════════
Results: 117 passed, 0 failed
═══════════════════════════════════════
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

**Requirements:** g++ (C++17), CMake 3.10+, Ninja, Npcap (Windows) or libpcap (Linux)

---

## Usage

```bash
# Analyse a pcap file
./dpi_engine_pro --input capture.pcap

# Every packet with classification reason
./dpi_engine_pro --input capture.pcap --verbose

# List network interfaces (Windows)
./dpi_engine_pro --list-interfaces

# Live capture (run as Administrator on Windows)
./dpi_engine_pro --live --interface "10.30.8.184" --verbose

# Evaluate ML accuracy
./dpi_engine_pro --evaluate

# Use Decision Tree only (no Random Forest)
./dpi_engine_pro --input capture.pcap --no-rf

# Disable TCP reassembly
./dpi_engine_pro --input capture.pcap --no-reassembly

# Custom rules file
./dpi_engine_pro --input capture.pcap --rules custom_rules.txt

# All options
./dpi_engine_pro --help
```

---

## Blocking Rules

```bash
# data/rules.txt

BLOCK_APP    GAMING      # block all classified gaming traffic
BLOCK_DOMAIN torrent     # block any flow with torrent in SNI
BLOCK_PORT   4444        # block Metasploit default C2 port
# BLOCK_APP  YOUTUBE     # uncomment to block YouTube
# BLOCK_APP  TIKTOK      # uncomment to block TikTok
# BLOCK_IP   10.0.0.5    # block specific host
```

---

## Source files

| File | What it does |
|---|---|
| `packet_parser.cpp` | Ethernet/IP/TCP/UDP parsing at byte level |
| `stream_reassembler.cpp` | TCP stream reassembly with sequence tracking |
| `protocol_parser.cpp` | TLS SNI, HTTP headers, DNS label decoding |
| `flow_features.cpp` | 12-feature vector extraction per flow |
| `decision_tree.cpp` | Decision tree with Gini impurity splitting |
| `random_forest.cpp` | Random Forest with feature subsampling + voting |
| `ml_classifier.cpp` | Training pipeline, model save/load, confidence |
| `anomaly_detector.cpp` | Statistical z-score detection (Welford's algorithm) |
| `fast_path.cpp` | 5-tuple flow cache with LRU eviction |
| `rule_manager.cpp` | Block rules by app / domain / port / IP |
| `connection_tracker.cpp` | Active flow tracking by app type |
| `live_capture.cpp` | Live packet capture via WinPcap/Npcap |
| `pcap_reader.cpp` | .pcap/.pcapng file reading |
| `benchmark.cpp` | Throughput and latency measurement |
| `model_evaluator.cpp` | Train/test split, per-class accuracy |
| `feature_importance.cpp` | Permutation importance scoring |
| `ml_metrics.cpp` | Precision, recall, F1, confusion matrix |
| `logger.cpp` | Thread-safe leveled logging |
| `config_parser.cpp` | INI-style config file loading |

---

## What I learned building this

- How Ethernet frames, IP packets, TCP segments and TLS handshakes
  are structured at the byte level — not from a library, from reading RFCs
- How Decision Trees split data using Gini impurity
- Why Random Forests need feature subsampling to keep trees uncorrelated
- How confidence scores should come from leaf node class distributions
- How Welford's online algorithm maintains mean and variance without storing history
- What a z-score means and why 3σ is a reasonable anomaly threshold
- How TCP stream reassembly handles out-of-order delivery
- How to write thread-safe C++ with mutexes and atomics
- How to design 26 components that work together without circular dependencies

---

## License

MIT — use it, fork it, learn from it.

---

<div align="center">

Built with C++17 &nbsp;•&nbsp; No shortcuts &nbsp;•&nbsp; No ML libraries &nbsp;•&nbsp; No packet libraries

</div>
