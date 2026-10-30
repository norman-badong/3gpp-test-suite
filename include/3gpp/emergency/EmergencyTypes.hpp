#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <span>
#include <optional>

namespace gpp::emergency {

// ============================================================================
// 3GPP Emergency Services Types (TS 23.167, TS 24.229, RFC 6442, RFC 5031)
// ============================================================================

/// Emergency Service Category (TS 23.167 §7.2)
enum class EmergencyCategory : uint8_t {
    Police           = 1,
    Ambulance        = 2,
    Fire             = 3,
    MarineGuard      = 4,
    MountainRescue   = 5,
    GeneralEmergency = 6,
};

/// Emergency Call Session Mode (TS 24.229)
enum class EmergencySessionMode : uint8_t {
    Normal           = 0,
    EmergencyOnly    = 1,  // UE in emergency mode (no SIM / limited service)
    EmergencyRegistered = 2, // Emergency registration performed
};

/// PSAP Callback Capability (TS 23.167)
enum class PsapCallbackCapability : uint8_t {
    NotSupported     = 0,
    Supported        = 1,
};

/// Location Information Type (RFC 6442 / PIDF-LO)
enum class LocationType : uint8_t {
    None             = 0,
    CivicAddress     = 1,  // RFC 5139 civic location
    Geodetic         = 2,  // RFC 6442 geodetic (lat/long/alt)
    Both             = 3,
};

/// Emergency Registration Type (TS 24.229 §5.1.2.2)
enum class EmergencyRegistrationType : uint8_t {
    InitialRegistration    = 1,
    ReRegistration         = 2,
    Deregistration         = 3,
};

/// SIP Priority Header Values (RFC 3261 / RFC 4412)
enum class SipPriority : uint8_t {
    Normal       = 0,
    NonUrgent    = 1,
    Urgent       = 2,
    Emergency    = 3,
};

/// Emergency Bearer QoS (TS 23.167, TS 29.212)
struct EmergencyQos {
    uint8_t qci{65};           // QCI 65 = Mission Critical (MCPTT) / 66 = MCVideo / 67 = MCData
    uint8_t arp_priority{1};   // Allocation/Retention Priority
    bool    preemption_capability{true};
    bool    preemption_vulnerability{false};
};

/// Civic Location (RFC 5139 subset for emergency)
struct CivicLocation {
    std::string country;           // ISO 3166 (e.g., "US")
    std::string state;             // A1 (state/province)
    std::string county;            // A2
    std::string city;              // A3
    std::string street;            // A4
    std::string house_number;      // A5
    std::string building;          // A6
    std::string floor;             // A7
    std::string room;              // A8
    std::string additional_info;   // A9
};

/// Geodetic Location (RFC 6442 / PIDF-LO)
struct GeodeticLocation {
    double latitude{0.0};      // degrees, WGS84
    double longitude{0.0};     // degrees, WGS84
    double altitude{0.0};      // meters
    float  horizontal_accuracy{0.0f};   // meters
    float  vertical_accuracy{0.0f};     // meters
    uint32_t confidence{95};   // percentage
    uint64_t timestamp{0};     // Unix epoch seconds
};

/// Complete Location Information
struct LocationInfo {
    LocationType type{LocationType::None};
    CivicLocation civic{};
    GeodeticLocation geodetic{};

    [[nodiscard]] bool has_location() const { return type != LocationType::None; }
};

/// Emergency Service URN (RFC 5031) - e.g., "urn:service:sos" or "urn:service:sos.police"
struct EmergencyServiceUrn {
    std::string urn{"urn:service:sos"};
    std::optional<EmergencyCategory> category{};

    static EmergencyServiceUrn from_category(EmergencyCategory cat) {
        EmergencyServiceUrn u;
        u.category = cat;
        switch (cat) {
            case EmergencyCategory::Police:           u.urn = "urn:service:sos.police"; break;
            case EmergencyCategory::Ambulance:        u.urn = "urn:service:sos.ambulance"; break;
            case EmergencyCategory::Fire:             u.urn = "urn:service:sos.fire"; break;
            case EmergencyCategory::MarineGuard:      u.urn = "urn:service:sos.marine"; break;
            case EmergencyCategory::MountainRescue:   u.urn = "urn:service:sos.mountain"; break;
            case EmergencyCategory::GeneralEmergency: u.urn = "urn:service:sos"; break;
        }
        return u;
    }
};

/// Emergency Call Context (carried through signaling)
struct EmergencyCallContext {
    EmergencyServiceUrn service_urn{};
    EmergencyCategory category{EmergencyCategory::GeneralEmergency};
    EmergencySessionMode mode{EmergencySessionMode::Normal};
    LocationInfo location{};
    EmergencyQos qos{};
    PsapCallbackCapability callback_cap{PsapCallbackCapability::NotSupported};
    std::string call_id{};           // SIP Call-ID
    std::string from_tag{};          // From tag
    std::string to_tag{};            // To tag
    uint32_t cseq{1};
};

} // namespace gpp::emergency