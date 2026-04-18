#include "live_capture.h"
#include <iostream>
#include <iomanip>
#include <chrono>
#include <cstring>

using namespace std;

LiveCapture::LiveCapture(int queue_size)
    : packet_queue(queue_size)
{}

LiveCapture::~LiveCapture()
{
    if (capturing) stopCapture();
    close();
}

double LiveCapture::getCurrentTimeMs() const
{
    auto now = chrono::high_resolution_clock::now();
    auto ms  = chrono::duration_cast<chrono::milliseconds>(now.time_since_epoch()).count();
    return (double)ms;
}

uint64_t LiveCapture::packetsCaptured() const
{
    return packets_captured.load();
}

#ifdef _WIN32

vector<NetworkInterface> LiveCapture::listInterfaces()
{
    vector<NetworkInterface> interfaces;

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
        cerr << "LiveCapture: WSAStartup failed" << endl;
        return interfaces;
    }

    ULONG buf_size = 15000;
    vector<uint8_t> buf(buf_size);
    PIP_ADAPTER_INFO adapter_info =
        (PIP_ADAPTER_INFO)buf.data();

    if (GetAdaptersInfo(adapter_info, &buf_size)
        != ERROR_SUCCESS) {
        buf.resize(buf_size);
        adapter_info = (PIP_ADAPTER_INFO)buf.data();
        if (GetAdaptersInfo(adapter_info, &buf_size)
            != ERROR_SUCCESS) {
            return interfaces;
        }
    }

    PIP_ADAPTER_INFO adapter = adapter_info;
    while (adapter) {
        NetworkInterface iface;
        iface.name        = adapter->AdapterName;
        iface.description = adapter->Description;
        iface.ip_address  =
            adapter->IpAddressList.IpAddress.String;
        iface.is_up =
            (iface.ip_address != "0.0.0.0");
        interfaces.push_back(iface);
        adapter = adapter->Next;
    }

    return interfaces;
}

bool LiveCapture::createRawSocket()
{
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
        cerr << "LiveCapture: WSAStartup failed" << endl;
        return false;
    }

    raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_IP);

    if (raw_socket == INVALID_SOCKET) {
        cerr << "LiveCapture: Cannot create raw socket" << endl;
        cerr << "  Run as Administrator!" << endl;
        return false;
    }

    sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = inet_addr(interface_name.c_str());

    if (bind(raw_socket, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        cerr << "LiveCapture: Cannot bind to " << interface_name << endl;
        cerr << "  Try using IP address e.g. 192.168.1.5" << endl;
        closesocket(raw_socket);
        raw_socket = INVALID_SOCKET;
        return false;
    }

    DWORD flag = 1;
    DWORD bytes_returned = 0;
    WSAIoctl(raw_socket, SIO_RCVALL,
             &flag, sizeof(flag),
             nullptr, 0,
             &bytes_returned, nullptr, nullptr);

    return true;
}

bool LiveCapture::open(const string& iface_name)
{
    interface_name = iface_name;
    if (!createRawSocket()) return false;
    cout << "LiveCapture: Opened interface "
         << iface_name << endl;
    return true;
}

void LiveCapture::captureLoop()
{
    vector<uint8_t> buf(65536);

    while (capturing) {
        int bytes = recv(raw_socket,
                        (char*)buf.data(),
                        (int)buf.size(), 0);

        if (bytes <= 0) {
            if (!capturing) break;
            continue;
        }

        RawPacket pkt;
        pkt.timestamp_ms = getCurrentTimeMs();
        pkt.original_len = (uint32_t)bytes;
        pkt.data.assign(buf.begin(),
                        buf.begin() + bytes);

        packet_queue.push(move(pkt));
        packets_captured++;
    }
}

void LiveCapture::close()
{
    if (raw_socket != INVALID_SOCKET) {
        closesocket(raw_socket);
        raw_socket = INVALID_SOCKET;
    }
    WSACleanup();
}

#else

vector<NetworkInterface> LiveCapture::listInterfaces()
{
    vector<NetworkInterface> interfaces;

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return interfaces;

    char buf[4096];
    struct ifconf ifc;
    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;

    if (ioctl(sock, SIOCGIFCONF, &ifc) < 0) {
        ::close(sock);
        return interfaces;
    }

    struct ifreq* ifr = ifc.ifc_req;
    int n = ifc.ifc_len / sizeof(struct ifreq);

    for (int i = 0; i < n; i++) {
        NetworkInterface iface;
        iface.name = ifr[i].ifr_name;

        struct sockaddr_in* addr =
            (struct sockaddr_in*)&ifr[i].ifr_addr;
        iface.ip_address = inet_ntoa(addr->sin_addr);

        struct ifreq flags_req;
        strncpy(flags_req.ifr_name,
                ifr[i].ifr_name, IFNAMSIZ);
        if (ioctl(sock, SIOCGIFFLAGS,
                  &flags_req) == 0) {
            iface.is_up =
                (flags_req.ifr_flags & IFF_UP) != 0;
        }

        interfaces.push_back(iface);
    }

    ::close(sock);
    return interfaces;
}

bool LiveCapture::createRawSocket()
{
    raw_socket = socket(AF_PACKET,
                        SOCK_RAW,
                        htons(0x0003));

    if (raw_socket < 0) {
        cerr << "LiveCapture: Cannot create socket" << endl;
        cerr << "  Run as root: sudo ./dpi_mt" << endl;
        return false;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name,
            interface_name.c_str(),
            IFNAMSIZ - 1);

    if (ioctl(raw_socket, SIOCGIFINDEX, &ifr) < 0) {
        cerr << "LiveCapture: Interface not found: "
             << interface_name << endl;
        ::close(raw_socket);
        raw_socket = -1;
        return false;
    }

    return true;
}

bool LiveCapture::open(const string& iface_name)
{
    interface_name = iface_name;
    if (!createRawSocket()) return false;
    cout << "LiveCapture: Opened interface "
         << iface_name << endl;
    return true;
}

void LiveCapture::captureLoop()
{
    vector<uint8_t> buf(65536);

    while (capturing) {
        int bytes = recv(raw_socket,
                        buf.data(),
                        buf.size(), 0);

        if (bytes <= 0) {
            if (!capturing) break;
            continue;
        }

        RawPacket pkt;
        pkt.timestamp_ms = getCurrentTimeMs();
        pkt.original_len = (uint32_t)bytes;
        pkt.data.assign(buf.begin(),
                        buf.begin() + bytes);

        packet_queue.push(move(pkt));
        packets_captured++;
    }
}

void LiveCapture::close()
{
    if (raw_socket >= 0) {
        ::close(raw_socket);
        raw_socket = -1;
    }
}

#endif

void LiveCapture::startCapture()
{
    capturing = true;
    capture_thread = thread(
        &LiveCapture::captureLoop, this);
    cout << "LiveCapture: Capture started" << endl;
}

void LiveCapture::stopCapture()
{
    capturing = false;
    packet_queue.setDone();
    if (capture_thread.joinable()) {
        capture_thread.join();
    }
    cout << "LiveCapture: Stopped. Captured "
         << packets_captured << " packets" << endl;
}

bool LiveCapture::getNextPacket(RawPacket& packet)
{
    return packet_queue.tryPop(packet);
}

void LiveCapture::printInterfaces()
{
    auto interfaces = listInterfaces();

    cout << "\n=== Available Network Interfaces ===\n";

    if (interfaces.empty()) {
        cout << "No interfaces found\n";
        cout << "(Run as Administrator/root)\n";
        return;
    }

    for (size_t i = 0; i < interfaces.size(); i++) {
        const auto& iface = interfaces[i];
        cout << "[" << i << "] "
             << setw(20) << iface.name
             << " IP: " << setw(16) << iface.ip_address
             << (iface.is_up ? " [UP]" : " [DOWN]")
             << "\n";
        if (!iface.description.empty() &&
            iface.description != iface.name) {
            cout << "     " << iface.description << "\n";
        }
    }
    cout << "====================================\n\n";
}
