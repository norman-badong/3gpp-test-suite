#pragma once

#include <string>
#include <string_view>
#include <iostream>
#include <sstream>
#include <mutex>
#include <chrono>
#include <iomanip>
#include <cstdint>
#include <span>

namespace gpp::common {

enum class LogLevel {
    DEBUG,
    INFO,
    WARN,
    ERROR
};

class Logger {
public:
    static Logger& instance();

    void set_level(LogLevel level);
    LogLevel get_level() const;

    void log(LogLevel level, std::string_view module, std::string_view message);
    void hexdump(LogLevel level, std::string_view module, std::string_view description, std::span<const uint8_t> data);

private:
    Logger() = default;
    LogLevel current_level_{LogLevel::DEBUG};
    std::mutex mutex_;

    static const char* level_to_color(LogLevel level);
    static const char* level_to_string(LogLevel level);
};

// Macro helpers
#define GPP_LOG_DEBUG(module, msg) ::gpp::common::Logger::instance().log(::gpp::common::LogLevel::DEBUG, module, msg)
#define GPP_LOG_INFO(module, msg)  ::gpp::common::Logger::instance().log(::gpp::common::LogLevel::INFO,  module, msg)
#define GPP_LOG_WARN(module, msg)  ::gpp::common::Logger::instance().log(::gpp::common::LogLevel::WARN,  module, msg)
#define GPP_LOG_ERROR(module, msg) ::gpp::common::Logger::instance().log(::gpp::common::LogLevel::ERROR, module, msg)
#define GPP_HEXDUMP(module, desc, span) ::gpp::common::Logger::instance().hexdump(::gpp::common::LogLevel::DEBUG, module, desc, span)

} // namespace gpp::common
