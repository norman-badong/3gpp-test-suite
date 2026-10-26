#include "3gpp/common/Logger.hpp"

namespace gpp::common {

Logger& Logger::instance() {
    static Logger logger;
    return logger;
}

void Logger::set_level(LogLevel level) {
    std::lock_guard<std::mutex> lock(mutex_);
    current_level_ = level;
}

LogLevel Logger::get_level() const {
    return current_level_;
}

const char* Logger::level_to_color(LogLevel level) {
    switch (level) {
        case LogLevel::DEBUG: return "\033[36m"; // Cyan
        case LogLevel::INFO:  return "\033[32m"; // Green
        case LogLevel::WARN:  return "\033[33m"; // Yellow
        case LogLevel::ERROR: return "\033[31m"; // Red
    }
    return "\033[0m";
}

const char* Logger::level_to_string(LogLevel level) {
    switch (level) {
        case LogLevel::DEBUG: return "DEBUG";
        case LogLevel::INFO:  return "INFO ";
        case LogLevel::WARN:  return "WARN ";
        case LogLevel::ERROR: return "ERROR";
    }
    return "UNKNOWN";
}

void Logger::log(LogLevel level, std::string_view module, std::string_view message) {
    if (level < current_level_) return;

    auto now = std::chrono::system_clock::now();
    auto timer = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;

    std::tm bt{};
#if defined(_WIN32)
    localtime_s(&bt, &timer);
#else
    localtime_r(&timer, &bt);
#endif

    std::lock_guard<std::mutex> lock(mutex_);
    std::cout << "\033[90m"
              << std::put_time(&bt, "%H:%M:%S")
              << '.' << std::setfill('0') << std::setw(3) << ms.count()
              << " \033[0m"
              << level_to_color(level) << "[" << level_to_string(level) << "]\033[0m "
              << "\033[1;35m[" << module << "]\033[0m "
              << message << "\n";
    std::cout.flush();
}

void Logger::hexdump(LogLevel level, std::string_view module, std::string_view description, std::span<const uint8_t> data) {
    if (level < current_level_) return;

    std::ostringstream ss;
    ss << description << " (" << data.size() << " bytes):\n";

    constexpr size_t bytes_per_line = 16;
    for (size_t i = 0; i < data.size(); i += bytes_per_line) {
        // Offset
        ss << "  \033[90m" << std::hex << std::setfill('0') << std::setw(4) << i << ": \033[0m";

        // Hex bytes
        for (size_t j = 0; j < bytes_per_line; ++j) {
            if (i + j < data.size()) {
                ss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(data[i + j]) << " ";
            } else {
                ss << "   ";
            }
            if (j == 7) ss << " ";
        }

        // ASCII representation
        ss << " |";
        for (size_t j = 0; j < bytes_per_line && (i + j) < data.size(); ++j) {
            uint8_t c = data[i + j];
            if (c >= 32 && c <= 126) {
                ss << static_cast<char>(c);
            } else {
                ss << '.';
            }
        }
        ss << "|\n";
    }

    log(level, module, ss.str());
}

} // namespace gpp::common
