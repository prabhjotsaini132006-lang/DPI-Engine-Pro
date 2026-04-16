#include "stats_dashboard.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <chrono>
#include <ctime>

using namespace std;

StatsDashboard::StatsDashboard(int interval_sec)
    : interval_sec(interval_sec)
{}

StatsDashboard::~StatsDashboard()
{
    if (running) stop();
}

void StatsDashboard::start(
    const DPIStats*          stats,
    const FastPath*          fast_path,
    const ConnectionTracker* tracker)
{
    stats_ptr    = stats;
    fastpath_ptr = fast_path;
    tracker_ptr  = tracker;
    running      = true;

    dashboard_thread = thread(
        &StatsDashboard::dashboardLoop, this);

    cout << "StatsDashboard: Started "
         << "(updating every "
         << interval_sec << "s)" << endl;
}

void StatsDashboard::stop()
{
    running = false;
    if (dashboard_thread.joinable()) {
        dashboard_thread.join();
    }
    cout << "StatsDashboard: Stopped" << endl;
}

void StatsDashboard::dashboardLoop()
{
    while (running) {
        // Sleep in small intervals to check running flag
        for (int i = 0; i < interval_sec * 10; i++) {
            if (!running) return;
            this_thread::sleep_for(
                chrono::milliseconds(100));
        }

        if (running) {
            printSnapshot();
        }
    }
}

void StatsDashboard::printSnapshot() const
{
    if (!stats_ptr) return;

    string time_str = getCurrentTime();

    uint64_t packets  = stats_ptr->packets_processed;
    uint64_t flows    = stats_ptr->flows_classified;
    uint64_t blocked  = stats_ptr->flows_blocked;
    uint64_t sni      = stats_ptr->sni_classified;
    uint64_t ml       = stats_ptr->ml_classified;
    uint64_t cache    = stats_ptr->cache_hits;
    uint64_t unknown  = stats_ptr->unknown_flows;

    double hit_rate = 0.0;
    if (fastpath_ptr) {
        hit_rate = fastpath_ptr->hitRate() * 100.0;
    }

    size_t active_flows = 0;
    if (tracker_ptr) {
        active_flows = tracker_ptr->flowCount();
    }

    cout << "\n[" << time_str << "] "
         << "═══ Live Stats ═══\n";
    cout << "  Packets:      "
         << formatNumber(packets)      << "\n";
    cout << "  Active flows: "
         << formatNumber(active_flows) << "\n";
    cout << "  Classified:   "
         << formatNumber(flows)        << "\n";
    cout << "  Via SNI:      "
         << formatNumber(sni)          << "\n";
    cout << "  Via ML:       "
         << formatNumber(ml)           << "\n";
    cout << "  Cache hits:   "
         << formatNumber(cache)
         << " (" << fixed << setprecision(1)
         << hit_rate << "%)\n";
    cout << "  Blocked:      "
         << formatNumber(blocked)      << "\n";
    cout << "  Unknown:      "
         << formatNumber(unknown)      << "\n";
    cout.flush();
}

string StatsDashboard::formatNumber(
    uint64_t n) const
{
    string s   = to_string(n);
    string out = "";
    int    cnt = 0;

    for (int i = (int)s.size() - 1; i >= 0; i--) {
        if (cnt > 0 && cnt % 3 == 0) {
            out = "," + out;
        }
        out = s[i] + out;
        cnt++;
    }
    return out;
}

string StatsDashboard::getCurrentTime() const
{
    auto   now = chrono::system_clock::now();
    time_t t   = chrono::system_clock::to_time_t(now);

    char      buf[20];
    struct tm tm_info;

#ifdef _WIN32
    localtime_s(&tm_info, &t);
#else
    localtime_r(&t, &tm_info);
#endif

    strftime(buf, sizeof(buf), "%H:%M:%S", &tm_info);
    return string(buf);
}