#ifndef FAST_PATH_H
#define FAST_PATH_H

#include "types.h"
#include "flow_features.h"
#include <unordered_map>
#include <mutex>
#include <chrono>

// ─────────────────────────────────────────
// Fast Path Cache
// Once a flow is classified, cache the result
// Next packet from same flow → instant lookup
// No need to run ML again
// ─────────────────────────────────────────
struct CacheEntry {
    AppType app_type   = AppType::UNKNOWN;
    bool    blocked    = false;
    double  confidence = 0.0;
    int     hit_count  = 0;      // how many times this was used
    double  created_ms = 0.0;    // when was this cached
};

class FastPath {
public:
    FastPath(int cache_timeout_sec = 300,
             int max_entries       = 50000);

    // Check if flow is in cache
    // Returns true if found, fills entry
    bool lookup(const FiveTuple& tuple,
                CacheEntry& entry);

    // Add or update cache entry
    void insert(const FiveTuple& tuple,
                AppType  app_type,
                bool     blocked,
                double   confidence,
                double   timestamp_ms);

    // Remove expired entries
    int evictExpired(double current_time_ms);

    // Clear entire cache
    void clear();

    // Cache statistics
    size_t size()       const;
    size_t hitCount()   const;
    size_t missCount()  const;
    double hitRate()    const;

    // Print cache stats
    void printStats() const;

private:
    std::unordered_map<FiveTuple,
                       CacheEntry,
                       FiveTupleHash> cache;
    mutable std::mutex mutex;

    int    cache_timeout_sec;
    int    max_entries;
    size_t total_hits   = 0;
    size_t total_misses = 0;

    // Evict oldest entry when cache is full
    void evictOldest();
};

#endif // FAST_PATH_H