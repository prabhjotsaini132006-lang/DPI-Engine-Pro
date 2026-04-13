#include "load_balancer.h"
#include <iostream>

using namespace std;

LoadBalancer::LoadBalancer(int num_workers,
                           int queue_size)
    : num_workers(num_workers),
      queue_size(queue_size)
{
    // Create one queue per worker
    for (int i = 0; i < num_workers; i++) {
        queues.push_back(
            new TSQueue<RawPacket>(queue_size));
    }
}

LoadBalancer::~LoadBalancer()
{
    if (running) shutdown();

    for (auto* q : queues) {
        delete q;
    }
    queues.clear();
}

void LoadBalancer::start(
    function<void(RawPacket&, int)> worker_fn)
{
    running = true;

    cout << "LoadBalancer: Starting "
         << num_workers
         << " worker threads" << endl;

    for (int i = 0; i < num_workers; i++) {
        workers.emplace_back(
            &LoadBalancer::workerLoop,
            this,
            i,
            queues[i],
            worker_fn
        );
    }
}

void LoadBalancer::submit(RawPacket packet)
{
    if (!running) return;

    // Round robin distribution
    uint64_t idx = round_robin.fetch_add(1)
                   % num_workers;

    queues[idx]->push(move(packet));
    submitted++;
}

void LoadBalancer::shutdown()
{
    cout << "LoadBalancer: Shutting down..." << endl;

    // Signal all queues done
    for (auto* q : queues) {
        q->setDone();
    }

    // Wait for all workers to finish
    for (auto& t : workers) {
        if (t.joinable()) t.join();
    }

    workers.clear();
    running = false;

    cout << "LoadBalancer: All workers finished"
         << endl;
    cout << "LoadBalancer: Submitted="
         << submitted
         << " Processed=" << processed << endl;
}

void LoadBalancer::workerLoop(
    int worker_id,
    TSQueue<RawPacket>* queue,
    function<void(RawPacket&, int)> worker_fn)
{
    RawPacket packet;

    while (queue->pop(packet)) {
        worker_fn(packet, worker_id);
        processed++;
    }
}

uint64_t LoadBalancer::totalSubmitted() const
{
    return submitted;
}

uint64_t LoadBalancer::totalProcessed() const
{
    return processed;
}