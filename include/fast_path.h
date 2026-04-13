
#ifndef FAST_PATH_H
#define FAST_PATH_H

#include "types.h"
#include "flow_features.h"
#include <unordered_map>
#include <mutex>

struct CacheEntry {
    AppType app_type   = AppType::UNKNOWN;
    bool    blocked    = false;
    double  confidence = 0.0;
    int     hit_count  = 0;
    double  created_ms = 0.0;
};

class FastPath {
public:
    FastPath(int cache_timeout_sec = 300,
             int max_entries       = 50000);

    bool   lookup(const FiveTuple& tuple,
                  CacheEntry& entry);
    void   insert(const FiveTuple& tuple,
                  AppType  app_type,
                  bool     blocked,
                  double   confidence,
                  double   timestamp_ms);
    int    evictExpired(double current_time_ms);
    void   clear();
    size_t size()      const;
    size_t hitCount()  const;
    size_t missCount() const;
    double hitRate()   const;
    void   printStats() const;

private:
    std::unordered_map<FiveTuple,
                       CacheEntry,
                       FiveTupleHash> cache;
    mutable std::mutex mtx;
    int    cache_timeout_sec;
    int    max_entries;
    size_t total_hits   = 0;
    size_t total_misses = 0;

    void evictOldest();
};

#endif // FAST_PATH_H