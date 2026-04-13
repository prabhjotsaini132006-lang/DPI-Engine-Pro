# DPI-Engine-Pro v2.0.0



!\[Build Status](https://github.com/prabhjotsaini132006-lang/DPI-Engine-Pro/actions/workflows/build.yml/badge.svg)

!\[C++17](https://img.shields.io/badge/C%2B%2B-17-blue)

!\[License: MIT](https://img.shields.io/badge/License-MIT-green)



> ML-powered Deep Packet Inspection engine in C++



\## What is this?



DPI-Engine-Pro is an improved Deep Packet Inspection engine that uses Machine Learning to classify network traffic even when domain names are hidden or encrypted.



Original approach: substring matching on SNI domain names.

This project: hybrid SNI + Decision Tree ML classifier.

## Comparison: Original vs DPI-Engine-Pro

| Feature | Original | v1.0.0 | v2.0.0 |
|---|---|---|---|
| Classification | Substring | Decision Tree | Random Forest |
| Without SNI | NO | YES | YES |
| Confidence score | NO | YES | YES |
| Rule manager | Basic | Basic | File-based |
| Flow expiry | NO | NO | YES |
| Fast path cache | NO | NO | YES |
| Multi-threading | Basic | NO | YES |
| Tests | NO | 17 | 24 |


\## Why ML?



| Situation | Old Approach | DPI-Engine-Pro |

|---|---|---|

| YouTube via googlevideo.com | UNKNOWN | YOUTUBE |

| TLS 1.3 encrypted SNI | UNKNOWN | ML predicts from behavior |

| New unknown app | UNKNOWN | ML predicts from patterns |

| DNS query | DNS | DNS |



\## How it Works



.pcap file

|

Parse Ethernet/IP/TCP/UDP headers

|

Extract TLS SNI domain name

|

Build flow feature vector

(packet size, duration, port, protocol, bytes/sec...)

|

Hybrid classification:

SNI available?  use SNI (100% accurate)

SNI missing?    use Decision Tree ML

|

Report: app type, blocked flows, classification stats



\## Features



\- Reads real .pcap network capture files

\- Parses Ethernet, IP, TCP, UDP headers byte by byte

\- Extracts TLS SNI domain names from TLS handshake

\- 12 flow features extracted per connection

\- Decision Tree ML classifier trained on labeled flow data

\- Hybrid strategy: SNI when available, ML when not

\- Save and load trained model (no retraining on every run)

\- 17 unit tests passing



\## ML Pipeline



TRAINING (done once):

labeled flows CSV

|

extract FlowFeatures

|

build Decision Tree

(find best Gini split at each node)

|

save model to file

RUNTIME (every new flow):

new packets arrive

|

update FlowFeatures

|

SNI found?  sniToAppType()

no SNI?     DecisionTree::predict()

|

apply blocking rules



\## Architecture



include/

flow\_features.h    - FlowFeatures struct (12 features)

decision\_tree.h    - Node struct + DecisionTree class

ml\_classifier.h    - MLClassifier wrapper

training\_data.h    - CSV loader

types.h            - FiveTuple, Flow, AppType, sniToAppType

pcap\_reader.h      - reads raw .pcap files

packet\_parser.h    - parses Ethernet/IP/TCP/UDP

sni\_extractor.h    - extracts domain from TLS handshake

src/

flow\_features.cpp  - update() and finalize()

decision\_tree.cpp  - train, predict, save, load

ml\_classifier.cpp  - loadOrTrain wrapper

training\_data.cpp  - CSV parsing

pcap\_reader.cpp    - pcap file reading

packet\_parser.cpp  - header parsing

sni\_extractor.cpp  - TLS SNI extraction

main\_pro.cpp       - main program

data/

training\_flows.csv - labeled training data

model.txt          - saved trained model

tests/

test\_classifier.cpp - 17 unit tests



\## Building



Requirements:

\- g++ with C++17 support

\- CMake 3.10 or newer

\- make or ninja



```bash

git clone https://github.com/prabhjotsaini132006-lang/DPI-Engine-Pro.git

cd DPI-Engine-Pro

mkdir build \&\& cd build

cmake .. -DCMAKE\_BUILD\_TYPE=Release

make

```



\## Usage



```bash

\# Basic usage

./dpi\_engine\_pro capture.pcap



\# With verbose packet output

./dpi\_engine\_pro capture.pcap --verbose



\# Custom training data and model

./dpi\_engine\_pro capture.pcap --csv data/training\_flows.csv --model data/model.txt

```



\## Sample Output

DPI-Engine-Pro v1.0

ML-powered Deep Packet Inspection

Loading ML Model...

MLClassifier: Found and loaded saved model!

Opening PCAP File...

PcapReader: Opened capture.pcap

Processing Packets...

=======================================

DPI-Engine-Pro Report

Total packets processed: 1500

Total flows detected:    47

App Distribution

YOUTUBE:   12

DNS:       18

WHATSAPP:   8

ZOOM:       5

HTTP:       4

Classification Method

Via SNI: 31 flows (100% accurate)

Via ML:  16 flows (ML predicted)

Blocked Flows

Blocked: 0 flows



\## Running Tests



```bash

cd build

./test\_classifier

```



Expected output:

Results: 17 passed, 0 failed



\## Training on Custom Data



The training CSV format:

total\_packets,total\_bytes,avg\_packet\_size,max\_packet\_size,min\_packet\_size,duration\_ms,packets\_per\_sec,bytes\_per\_sec,avg\_inter\_arrival,dst\_port,protocol,has\_tls,label

47,185000,3936,1400,800,2500,18,74000,53,443,6,1,YOUTUBE

2,100,50,60,40,5,400,20000,2,53,17,0,DNS



Supported labels: YOUTUBE, FACEBOOK, ZOOM, WHATSAPP, DNS, HTTP, HTTPS, GAMING



\## Comparison: Old vs New



| Feature | Original Packet\_analyzer | DPI-Engine-Pro |

|---|---|---|

| Classification | Substring matching | Decision Tree ML |

| Works without SNI | NO | YES |

| Handles CDNs | NO | YES |

| Handles encrypted SNI | NO | YES |

| New apps | Manual code change | Retrain model |



\## Contributing



1\. Fork the repository

2\. Create a feature branch: git checkout -b feature/my-feature

3\. Commit changes: git commit -m "feat: add my feature"

4\. Push branch: git push origin feature/my-feature

5\. Open a Pull Request



\## License



MIT License - free to use, modify, and distribute.



