#include "benchmark.h"
#include <sstream>

using namespace std;
using namespace std::chrono;

void Benchmark::start(const string& name)
{
    if (!processing_started) {
        processing_start   = Clock::now();
        processing_started = true;
    }
    start_times[name] = Clock::now();
}

void Benchmark::stop(const string& name)
{
    auto it = start_times.find(name);
    if (it == start_times.end()) return;

    auto end      = Clock::now();
    auto duration = duration_cast<microseconds>(
        end - it->second).count();

    durations_ms[name] =
        (double)duration / 1000.0;

    total_latency_us += (uint64_t)duration;
}

void Benchmark::recordPacket(uint64_t bytes)
{
    if (!processing_started) {
        processing_start   = Clock::now();
        processing_started = true;
    }
    total_packets++;
    total_bytes += bytes;
}

void Benchmark::recordClassification()
{
    total_classifications++;
}

double Benchmark::packetsPerSecond() const
{
    if (!processing_started || total_packets == 0)
        return 0.0;

    auto now      = Clock::now();
    auto elapsed  = duration_cast<microseconds>(
        now - processing_start).count();

    if (elapsed == 0) return 0.0;

    return (double)total_packets /
           ((double)elapsed / 1000000.0);
}

double Benchmark::megabytesPerSecond() const
{
    if (!processing_started || total_bytes == 0)
        return 0.0;

    auto now     = Clock::now();
    auto elapsed = duration_cast<microseconds>(
        now - processing_start).count();

    if (elapsed == 0) return 0.0;

    return ((double)total_bytes / 1048576.0) /
           ((double)elapsed / 1000000.0);
}

double Benchmark::avgLatencyUs() const
{
    if (total_classifications == 0) return 0.0;
    return (double)total_latency_us /
           (double)total_classifications;
}

void Benchmark::reset()
{
    start_times.clear();
    durations_ms.clear();
    processing_started    = false;
    total_packets         = 0;
    total_bytes           = 0;
    total_classifications = 0;
    total_latency_us      = 0;
}

string Benchmark::formatBytes(uint64_t bytes) const
{
    if (bytes < 1024)
        return to_string(bytes) + " B";
    if (bytes < 1048576)
        return to_string(bytes/1024) + " KB";
    if (bytes < 1073741824)
        return to_string(bytes/1048576) + " MB";
    return to_string(bytes/1073741824) + " GB";
}

string Benchmark::formatNum(uint64_t n) const
{
    string s   = to_string(n);
    string out = "";
    int    cnt = 0;
    for (int i = (int)s.size()-1; i >= 0; i--) {
        if (cnt > 0 && cnt % 3 == 0) out = "," + out;
        out = s[i] + out;
        cnt++;
    }
    return out;
}

void Benchmark::printReport() const
{
    cout << "\n════════════════════════════════════\n";
    cout << "     Performance Benchmark Report    \n";
    cout << "════════════════════════════════════\n";

    cout << fixed << setprecision(2);

    cout << "Packets processed:  "
         << formatNum(total_packets) << "\n";
    cout << "Total data:         "
         << formatBytes(total_bytes) << "\n";
    cout << "Classifications:    "
         << formatNum(total_classifications) << "\n";
    cout << "\n";
    cout << "Throughput:         "
         << packetsPerSecond()
         << " packets/sec\n";
    cout << "Data rate:          "
         << megabytesPerSecond()
         << " MB/sec\n";
    cout << "Avg latency:        "
         << avgLatencyUs()
         << " microseconds\n";

    if (!durations_ms.empty()) {
        cout << "\nOperation Timings:\n";
        for (const auto& pair : durations_ms) {
            cout << "  " << setw(20) << pair.first
                 << ": " << pair.second
                 << " ms\n";
        }
    }
    cout << "════════════════════════════════════\n";
}