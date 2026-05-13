#pragma once

#include "../../core/Application.hpp"
#include "../../core/SwitchManager.hpp"
#include "../../core/Controller.hpp"
#include "../../core/Loader.hpp"
#include "../../core/Config.hpp"
#include "../../core/api/OFConnection.hpp"

#include <fluid/of13msg.hh>
#include <fluid/of13/openflow-13.h>

#include <QObject>
#include <QTimer>

#include <string>
#include <unordered_map>
#include <deque>
#include <mutex>
#include <vector>

namespace runos {

struct FlowIdParts {
    std::string dpid;
    std::string proto;
    std::string src_ip;
    std::string dst_ip;
    uint16_t    src_port = 0;
    uint16_t    dst_port = 0;
};

struct FlagEvent {
    double  ts  = 0.0;
    uint8_t syn = 0;
    uint8_t fin = 0;
    uint8_t rst = 0;
};

struct FlowRates {
    double syn_rate = 0.0;
    double fin_rate = 0.0;
    double rst_rate = 0.0;
};

class GuardApp : public Application {
    Q_OBJECT
public:
    void init(Loader* loader, const Config& config) override;
    void startUp(Loader* loader) override;
    
    std::string provides() const override { return "guard-app"; }
    
    DependencyList dependsOn(const Config& config) const override;

private slots:
    void onSwitchUp(SwitchPtr sw);
    void pollFlowStats();

private:
    struct ParsedPkt {
        bool        valid     = false;
        bool        is_tcp    = false;
        std::string src_ip;
        std::string dst_ip;
        uint16_t    src_port  = 0;
        uint16_t    dst_port  = 0;
        uint8_t     tcp_flags = 0;
    };

    double window_sec_ = 5.0;
    double poll_sec_ = 1.0;
    double syn_flood_rate_thr_ = 200.0;
    double port_scan_thr_ = 20.0;
    uint16_t drop_table_ = 0;
    uint32_t drop_priority_ = 50000;
    uint32_t drop_idle_timeout_ = 300;

    SwitchManager* sw_manager_ = nullptr;
    Controller*    controller_ = nullptr;
    QTimer*        poll_timer_ = nullptr;

    mutable std::mutex mu_;
    std::unordered_map<std::string, std::deque<FlagEvent>> flag_events_;
    std::unordered_map<std::string, std::unordered_map<uint16_t, double>> dst_port_seen_;
    std::unordered_map<uint64_t, OFConnectionPtr> connections_;

    void onPacketIn(fluid_msg::of13::PacketIn& pi, OFConnectionPtr conn);
    void installDropRule(const FlowIdParts& p);

    FlowRates computeFlagRatesLocked(const std::string& flow_id, double now);
    double computeUniqueDstPortsLocked(const std::string& flow_id, double now);
    void cleanupOldEventsLocked(std::deque<FlagEvent>& q, double now);

    static ParsedPkt parseFrame(const uint8_t* data, size_t len);
    static FlowIdParts parseFlowId(const std::string& fid);
    static std::string buildFlowId(const FlowIdParts& p);
    static std::string dpidToStr(uint64_t dpid);
    static std::string ipToStr(uint32_t ip);
};

} // namespace runos

