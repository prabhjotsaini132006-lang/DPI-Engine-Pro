#ifndef LOGGER_H
#define LOGGER_H

#include <string>
#include <fstream>
#include <mutex>
#include <sstream>
#include <iostream>
#include <chrono>
#include <ctime>

enum class LogLevel {
    DEBUG = 0,
    INFO  = 1,
    WARN  = 2,
    ERROR = 3
};

class Logger {
public:
    static Logger& instance();

    void setLevel(LogLevel level);
    void setLogFile(const std::string& filename);
    void setConsoleOutput(bool enabled);

    void debug(const std::string& msg,
               const std::string& component = "");
    void info(const std::string& msg,
              const std::string& component = "");
    void warn(const std::string& msg,
              const std::string& component = "");
    void error(const std::string& msg,
               const std::string& component = "");

    void close();

private:
    Logger();
    ~Logger();

    Logger(const Logger&)            = delete;
    Logger& operator=(const Logger&) = delete;

    void   log(LogLevel           level,
               const std::string& msg,
               const std::string& component);

    std::string levelToString(LogLevel level) const;
    std::string getCurrentTime()              const;

    LogLevel           min_level      = LogLevel::INFO;
    bool               console_output = true;
    std::ofstream      log_file;
    mutable std::mutex mtx;
};

#define LOG_DEBUG(msg) \
    Logger::instance().debug(msg)
#define LOG_INFO(msg) \
    Logger::instance().info(msg)
#define LOG_WARN(msg) \
    Logger::instance().warn(msg)
#define LOG_ERROR(msg) \
    Logger::instance().error(msg)

#define LOG_DEBUG_C(component, msg) \
    Logger::instance().debug(msg, component)
#define LOG_INFO_C(component, msg) \
    Logger::instance().info(msg, component)
#define LOG_WARN_C(component, msg) \
    Logger::instance().warn(msg, component)
#define LOG_ERROR_C(component, msg) \
    Logger::instance().error(msg, component)

#endif // LOGGER_H