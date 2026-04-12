#ifndef THREAD_SAFE_QUEUE_H
#define THREAD_SAFE_QUEUE_H

#include <queue>
#include <mutex>
#include <condition_variable>
#include <chrono>

// ─────────────────────────────────────────
// Thread Safe Queue
// Multiple threads can push/pop safely
// ─────────────────────────────────────────
template<typename T>
class TSQueue {
public:
    TSQueue(size_t max_size = 10000)
        : max_size(max_size), done(false)
    {}

    // Push item to back of queue
    // Blocks if queue is full
    void push(T item)
    {
        std::unique_lock<std::mutex> lock(mutex);

        // Wait until queue has space
        not_full.wait(lock, [this] {
            return queue.size() < max_size || done;
        });

        if (done) return;

        queue.push(std::move(item));
        not_empty.notify_one();
    }

    // Pop item from front of queue
    // Blocks until item available
    // Returns false if queue is done and empty
    bool pop(T& item)
    {
        std::unique_lock<std::mutex> lock(mutex);

        // Wait until queue has items or is done
        not_empty.wait(lock, [this] {
            return !queue.empty() || done;
        });

        if (queue.empty()) return false;

        item = std::move(queue.front());
        queue.pop();
        not_full.notify_one();
        return true;
    }

    // Try to pop without blocking
    // Returns false immediately if empty
    bool tryPop(T& item)
    {
        std::unique_lock<std::mutex> lock(mutex);

        if (queue.empty()) return false;

        item = std::move(queue.front());
        queue.pop();
        not_full.notify_one();
        return true;
    }

    // Signal that no more items will be pushed
    void setDone()
    {
        std::unique_lock<std::mutex> lock(mutex);
        done = true;
        not_empty.notify_all();
        not_full.notify_all();
    }

    // Current number of items
    size_t size() const
    {
        std::unique_lock<std::mutex> lock(mutex);
        return queue.size();
    }

    // Is queue empty?
    bool empty() const
    {
        std::unique_lock<std::mutex> lock(mutex);
        return queue.empty();
    }

    // Reset for reuse
    void reset()
    {
        std::unique_lock<std::mutex> lock(mutex);
        while (!queue.empty()) queue.pop();
        done = false;
    }

private:
    std::queue<T>           queue;
    mutable std::mutex      mutex;
    std::condition_variable not_empty;
    std::condition_variable not_full;
    size_t                  max_size;
    bool                    done;
};

#endif // THREAD_SAFE_QUEUE_H