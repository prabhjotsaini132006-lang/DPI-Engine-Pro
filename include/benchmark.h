#ifndef BENCHMARK_H
#define BENCHMARK_H

#include <chrono>
#include <string>
#include <map>
#include <atomic>
#include <iostream>
#include <iomanip>

// ─────────────────────────────────────────
// Performance Benchmarker
// Tracks timing and throughput stats
// ─────────────────────────────────────────
class Benchmark {
public:
    // Start timing a named operation
    void start(const std::string& name);

    // Stop timing and record result
    void stop(const std::string& name);

    // Record packet processing
    void recordPacket(uint64_t bytes = 0);

    // Record flow classification
    void recordClassification();

    // Print full benchmark report
    void printReport() const;

    // Get throughput in packets/sec
    double packetsPerSecond() const;

    // Get throughput in MB/sec
    double megabytesPerSecond() const;

    // Get average latency in microseconds
    double avgLatencyUs() const;

    // Reset all stats
    void reset();

private:
    using Clock     = std::chrono::high_resolution_clock;
    using TimePoint = std::chrono::time_point<Clock>;

    // Timer entries
    std::map<std::string, TimePoint> start_times;
    std::map<std::string, double>    durations_ms;

    // Processing stats
    TimePoint  processing_start;
    bool       processing_started = false;

    std::atomic<uint64_t> total_packets       {0};
    std::atomic<uint64_t> total_bytes         {0};
    std::atomic<uint64_t> total_classifications {0};
    std::atomic<uint64_t> total_latency_us    {0};

    // Format bytes to human readable
    std::string formatBytes(uint64_t bytes) const;

    // Format number with commas
    std::string formatNum(uint64_t n) const;
};

#endif // BENCHMARK_H