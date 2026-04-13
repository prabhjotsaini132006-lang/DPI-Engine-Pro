#ifndef SIGNAL_HANDLER_H
#define SIGNAL_HANDLER_H

#include <atomic>
#include <csignal>
#include <iostream>

class SignalHandler {
public:
    static void setup();
    static bool shouldStop();
    static void reset();

private:
    static std::atomic<bool> stop_requested;
    static void handleSignal(int signal);
};

#endif // SIGNAL_HANDLER_H