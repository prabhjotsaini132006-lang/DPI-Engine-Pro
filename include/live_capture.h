#ifndef LIVE_CAPTURE_H
#define LIVE_CAPTURE_H

#include "pcap_reader.h"
#include "thread_safe_queue.h"
#include <string>
#include <vector>
#include <atomic>
#include <thread>
#include <functional>
#include <cstdint>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <iphlpapi.h>
#else
    #include <sys/socket.h>
    #include <sys/ioctl.h>
    #include <net/if.h>
    #include <arpa/inet.h>
    #include <unistd.h>
#endif

// ─────────────────────────────────────────
// Network Interface Info
// ─────────────────────────────────────────
struct NetworkInterface {
    std::string name;         // eth0, wlan0, etc
    std::string description;  // friendly name
    std::string ip_address;   // current IP
    bool        is_up = false;
};

// ─────────────────────────────────────────
// Live Packet Capture
// Captures packets from a live network interface
// Works on both Windows and Linux
// ─────────────────────────────────────────
class LiveCapture {
public:
    LiveCapture(int queue_size = 10000);
    ~LiveCapture();

    // List available network interfaces
    static std::vector<NetworkInterface>
        listInterfaces();

    // Open an interface for capture
    bool open(const std::string& interface_name);

    // Start capturing in background thread
    // Captured packets go into the queue
    void startCapture();

    // Stop capturing
    void stopCapture();

    // Get next captured packet
    // Returns false if no packets available
    bool getNextPacket(RawPacket& packet);

    // Is capture running?
    bool isCapturing() const { return capturing; }

    // How many packets captured so far
    uint64_t packetsCaptured() const;

    // Print available interfaces
    static void printInterfaces();

    // Close capture
    void close();

private:
    std::string              interface_name;
    std::atomic<bool>        capturing {false};
    std::atomic<uint64_t>    packets_captured {0};
    std::thread              capture_thread;
    TSQueue<RawPacket>       packet_queue;

#ifdef _WIN32
    SOCKET raw_socket = INVALID_SOCKET;
#else
    int    raw_socket = -1;
#endif

    // Background capture loop
    void captureLoop();

    // Create raw socket for interface
    bool createRawSocket();

    // Get current timestamp in ms
    double getCurrentTimeMs() const;
};

#endif // LIVE_CAPTURE_H