#ifndef STATS_DASHBOARD_H
#define STATS_DASHBOARD_H

#include "dpi_engine.h"
#include "fast_path.h"
#include "connection_tracker.h"
#include <thread>
#include <atomic>
#include <chrono>
#include <string>

// ─────────────────────────────────────────
// Live Statistics Dashboard
// Prints stats every N seconds in background
// ─────────────────────────────────────────
class StatsDashboard {
public:
    StatsDashboard(int interval_sec = 5);
    ~StatsDashboard();

    // Start background printing thread
    void start(const DPIStats*          stats,
               const FastPath*          fast_path,
               const ConnectionTracker* tracker);

    // Stop background thread
    void stop();

    // Print one snapshot manually
    void printSnapshot() const;

    // Is dashboard running?
    bool isRunning() const { return running; }

private:
    int                      interval_sec;
    std::atomic<bool>        running {false};
    std::thread              dashboard_thread;

    const DPIStats*          stats_ptr    = nullptr;
    const FastPath*          fastpath_ptr = nullptr;
    const ConnectionTracker* tracker_ptr  = nullptr;

    // Background loop
    void dashboardLoop();

    // Format number with commas
    std::string formatNumber(uint64_t n) const;

    // Get current time string
    std::string getCurrentTime() const;
};

#endif // STATS_DASHBOARD_H