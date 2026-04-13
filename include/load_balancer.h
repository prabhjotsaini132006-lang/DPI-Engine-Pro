#ifndef LOAD_BALANCER_H
#define LOAD_BALANCER_H

#include "types.h"
#include "pcap_reader.h"
#include "thread_safe_queue.h"
#include <vector>
#include <thread>
#include <atomic>
#include <functional>

// ─────────────────────────────────────────
// Load Balancer
// Distributes packets across worker threads
// Each worker has its own queue
// ─────────────────────────────────────────
class LoadBalancer {
public:
    LoadBalancer(int num_workers  = 4,
                 int queue_size   = 10000);

    ~LoadBalancer();

    // Start all worker threads
    // worker_fn is called for each packet
    void start(
        std::function<void(RawPacket&, int)> worker_fn);

    // Submit a packet for processing
    // Distributes using round robin
    void submit(RawPacket packet);

    // Signal no more packets coming
    // Wait for all workers to finish
    void shutdown();

    // Is load balancer running?
    bool isRunning() const { return running; }

    // Stats
    uint64_t totalSubmitted() const;
    uint64_t totalProcessed() const;

private:
    int                                  num_workers;
    int                                  queue_size;
    std::atomic<bool>                    running {false};
    std::atomic<uint64_t>                submitted {0};
    std::atomic<uint64_t>                processed {0};

    // One queue per worker
    std::vector<TSQueue<RawPacket>*>     queues;

    // Worker threads
    std::vector<std::thread>             workers;

    // Round robin counter
    std::atomic<uint64_t>                round_robin {0};

    // Worker thread function
    void workerLoop(
        int worker_id,
        TSQueue<RawPacket>* queue,
        std::function<void(RawPacket&, int)> worker_fn);
};

#endif // LOAD_BALANCER_H