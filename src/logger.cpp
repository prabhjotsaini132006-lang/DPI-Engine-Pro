#include "logger.h"

using namespace std;

Logger& Logger::instance()
{
    static Logger logger;
    return logger;
}

Logger::Logger()
    : min_level(LogLevel::INFO),
      console_output(true)
{}

Logger::~Logger()
{
    close();
}

void Logger::setLevel(LogLevel level)
{
    unique_lock<mutex> lock(mtx);
    min_level = level;
}

void Logger::setLogFile(const string& filename)
{
    unique_lock<mutex> lock(mtx);
    if (log_file.is_open()) log_file.close();
    log_file.open(filename, ios::app);
    if (!log_file.is_open()) {
        cerr << "Logger: Cannot open log file: "
             << filename << endl;
    }
}

void Logger::setConsoleOutput(bool enabled)
{
    unique_lock<mutex> lock(mtx);
    console_output = enabled;
}

void Logger::debug(const string& msg,
                   const string& component)
{
    log(LogLevel::DEBUG, msg, component);
}

void Logger::info(const string& msg,
                  const string& component)
{
    log(LogLevel::INFO, msg, component);
}

void Logger::warn(const string& msg,
                  const string& component)
{
    log(LogLevel::WARN, msg, component);
}

void Logger::error(const string& msg,
                   const string& component)
{
    log(LogLevel::ERROR, msg, component);
}

void Logger::log(LogLevel           level,
                 const string&      msg,
                 const string&      component)
{
    if (level < min_level) return;

    unique_lock<mutex> lock(mtx);

    string time_str  = getCurrentTime();
    string level_str = levelToString(level);

    ostringstream line;
    line << "[" << time_str  << "] "
         << "[" << level_str << "] ";

    if (!component.empty()) {
        line << "[" << component << "] ";
    }

    line << msg;

    string output = line.str();

    if (console_output) {
        if (level == LogLevel::ERROR ||
            level == LogLevel::WARN) {
            cerr << output << endl;
        } else {
            cout << output << endl;
        }
    }

    if (log_file.is_open()) {
        log_file << output << endl;
        log_file.flush();
    }
}

string Logger::levelToString(LogLevel level) const
{
    switch (level) {
        case LogLevel::DEBUG: return "DEBUG";
        case LogLevel::INFO:  return "INFO ";
        case LogLevel::WARN:  return "WARN ";
        case LogLevel::ERROR: return "ERROR";
        default:              return "?????";
    }
}

string Logger::getCurrentTime() const
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

    strftime(buf, sizeof(buf),
             "%Y-%m-%d %H:%M:%S", &tm_info);
    return string(buf);
}

void Logger::close()
{
    if (log_file.is_open()) {
        log_file.close();
    }
}