#include "fast_path.h"
#include <iostream>
#include <vector>
#include <limits>

using namespace std;

FastPath::FastPath(int cache_timeout_sec, int max_entries)
    : cache_timeout_sec(cache_timeout_sec),
      max_entries(max_entries),
      total_hits(0),
      total_misses(0)
{}

bool FastPath::lookup(const FiveTuple& tuple,
                      CacheEntry& entry)
{
    unique_lock<std::mutex> lock(mtx);
    auto it = cache.find(tuple);
    if (it == cache.end()) {
        total_misses++;
        return false;
    }
    it->second.hit_count++;
    entry = it->second;
    total_hits++;
    return true;
}

void FastPath::insert(const FiveTuple& tuple,
                      AppType  app_type,
                      bool     blocked,
                      double   confidence,
                      double   timestamp_ms)
{
    unique_lock<std::mutex> lock(mtx);
    if ((int)cache.size() >= max_entries) {
        evictOldest();
    }
    CacheEntry entry;
    entry.app_type   = app_type;
    entry.blocked    = blocked;
    entry.confidence = confidence;
    entry.hit_count  = 0;
    entry.created_ms = timestamp_ms;
    cache[tuple] = entry;
}

int FastPath::evictExpired(double current_time_ms)
{
    unique_lock<std::mutex> lock(mtx);
    double timeout_ms = cache_timeout_sec * 1000.0;
    vector<FiveTuple> to_remove;
    for (const auto& pair : cache) {
        double age = current_time_ms - pair.second.created_ms;
        if (age > timeout_ms) {
            to_remove.push_back(pair.first);
        }
    }
    for (const auto& tuple : to_remove) {
        cache.erase(tuple);
    }
    return (int)to_remove.size();
}

void FastPath::evictOldest()
{
    double oldest_time = numeric_limits<double>::max();
    FiveTuple oldest_tuple;
    bool found = false;
    for (const auto& pair : cache) {
        if (pair.second.created_ms < oldest_time) {
            oldest_time  = pair.second.created_ms;
            oldest_tuple = pair.first;
            found        = true;
        }
    }
    if (found) cache.erase(oldest_tuple);
}

void FastPath::clear()
{
    unique_lock<std::mutex> lock(mtx);
    cache.clear();
    total_hits   = 0;
    total_misses = 0;
}

size_t FastPath::size() const
{
    unique_lock<std::mutex> lock(mtx);
    return cache.size();
}

size_t FastPath::hitCount() const
{
    unique_lock<std::mutex> lock(mtx);
    return total_hits;
}

size_t FastPath::missCount() const
{
    unique_lock<std::mutex> lock(mtx);
    return total_misses;
}

double FastPath::hitRate() const
{
    unique_lock<std::mutex> lock(mtx);
    size_t total = total_hits + total_misses;
    if (total == 0) return 0.0;
    return (double)total_hits / (double)total;
}

void FastPath::printStats() const
{
    unique_lock<std::mutex> lock(mtx);
    cout << "=== Fast Path Cache Stats ===" << endl;
    cout << "  Entries:  " << cache.size()   << endl;
    cout << "  Hits:     " << total_hits     << endl;
    cout << "  Misses:   " << total_misses   << endl;
    size_t total = total_hits + total_misses;
    if (total > 0) {
        double rate = (double)total_hits / (double)total * 100.0;
        cout << "  Hit rate: " << rate << "%" << endl;
    }
}