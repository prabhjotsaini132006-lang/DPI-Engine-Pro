#include "signal_handler.h"

using namespace std;

atomic<bool> SignalHandler::stop_requested{false};

void SignalHandler::setup()
{
    signal(SIGINT,  handleSignal);
    signal(SIGTERM, handleSignal);
    cout << "SignalHandler: Ready "
         << "(press Ctrl+C to stop gracefully)"
         << endl;
}

bool SignalHandler::shouldStop()
{
    return stop_requested.load();
}

void SignalHandler::reset()
{
    stop_requested.store(false);
}

void SignalHandler::handleSignal(int signal)
{
    if (signal == SIGINT) {
        cout << "\nSignalHandler: Ctrl+C detected!"
             << endl;
    } else if (signal == SIGTERM) {
        cout << "\nSignalHandler: SIGTERM received!"
             << endl;
    }
    cout << "SignalHandler: Finishing current work..."
         << endl;
    stop_requested.store(true);
}