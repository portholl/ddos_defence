#include "GuardApp.hpp"
#include "../../../include/json11.hpp"

#include <fstream>
#include <iostream>
#include <chrono>
#include <iomanip>
#include <sstream>

namespace runos {

REGISTER_APPLICATION(GuardApp, {"controller", "switch-manager", ""})

static double nowSec() {
    return std::chrono::duration<double>(std::chrono::system_clock::now().time_since_epoch()).count();
}

std::string GuardApp::ipToStr(uint32_t ip) {
    return std::to_string((ip >> 24) & 0xFF) + "." +
           std::to_string((ip >> 16) & 0xFF) + "." +
           std::to_string((ip >>  8) & 0xFF) + "." +
           std::to_string((ip      ) & 0xFF);
}

std::string GuardApp::dpidToStr(uint64_t dpid) {
    std::ostringstream ss;
    ss << std::setw(16) << std::setfill('0') << std::hex << dpid;
    return ss.str();
}

void GuardApp::init(Loader* loader, const Config& config) {
    auto it = config.find("guard-app");
    if (it != config.end()) {
        auto& cfg = it->second;
        if (cfg["window_sec"].is_number()) window_sec_ = cfg["window_sec"].number_value();
        if (cfg["poll_sec"].is_number()) poll_sec_ = cfg["poll_sec"].number_value();
        if (cfg["syn_flood_rate_thr"].is_number()) syn_flood_rate_thr_ = cfg["syn_flood_rate_thr"].number_value();
        if (cfg["port_scan_thr"].is_number()) port_scan_thr_ = cfg["port_scan_thr"].number_value();
        if (cfg["drop_priority"].is_number()) drop_priority_ = cfg["drop_priority"].number_value();
        if (cfg["drop_idle_timeout"].is_number()) drop_idle_timeout_ = cfg["drop_idle_timeout"].number_value();
    }

    sw_manager_ = SwitchManager::get(loader);
    controller_ = Controller::get(loader);

    QObject::connect(sw_manager_, &SwitchManager::switchUp, this, &GuardApp::onSwitchUp);

    controller_->register_handler(
        [this](fluid_msg::of13::PacketIn& pi, OFConnectionPtr conn) mutable -> bool {
            this->onPacketIn(pi, conn);
            return false;
        }
    );

    poll_timer_ = new QTimer(this);
    QObject::connect(poll_timer_, &QTimer::timeout, this, &GuardApp::pollFlowStats);

    std::cout << "[GUARD] Init complete" << std::endl;
}

void GuardApp::startUp(Loader*) {
    poll_timer_->start(static_cast<int>(poll_sec_ * 1000.0));
    std::cout << "[GUARD] Timer started" << std::endl;
}

void GuardApp::onSwitchUp(SwitchPtr) {
    std::cout << "[GUARD] Switch connected" << std::endl;
}

void GuardApp::onPacketIn(fluid_msg::of13::PacketIn& pi, OFConnectionPtr conn) {
    uint64_t dpid_raw = conn->dpid();
    std::string dpid  = dpidToStr(dpid_raw);

    {
        std::lock_guard<std::mutex> lk(mu_);
        if (connections_.find(dpid_raw) == connections_.end()) {
            connections_[dpid_raw] = conn;
            
            fluid_msg::of13::FlowMod fm;
            fm.command(fluid_msg::of13::OFPFC_ADD);
            fm.table_id(0);
            fm.priority(100);
            fluid_msg::of13::EthType eth_type(0x0800);
            fm.add_oxm_field(eth_type);
            fluid_msg::of13::IPProto ip_proto(6);
            fm.add_oxm_field(ip_proto);
            
            fluid_msg::of13::ApplyActions aa;
            fluid_msg::of13::OutputAction output(fluid_msg::of13::OFPP_CONTROLLER, fluid_msg::of13::OFPCML_NO_BUFFER);
            aa.add_action(output);
            fm.add_instruction(aa);
            
            conn->send(fm);
            std::cout << "[GUARD] Catch TCP rule installed" << std::endl;
        }
    }

    const uint8_t* data = (const uint8_t*)pi.data();
    size_t len = pi.data_len();
    ParsedPkt pkt = parseFrame(data, len);
    
    if (!pkt.valid || !pkt.is_tcp) return;

    bool has_syn = (pkt.tcp_flags & 0x02) != 0;
    bool has_fin = (pkt.tcp_flags & 0x01) != 0;
    bool has_rst = (pkt.tcp_flags & 0x04) != 0;

    if (!has_syn && !has_fin && !has_rst) return;

    FlowIdParts p;
    p.dpid = dpid; p.proto = "tcp"; p.src_ip = pkt.src_ip; p.dst_ip = pkt.dst_ip;
    p.src_port = pkt.src_port; p.dst_port = pkt.dst_port;

    std::string flow_id = buildFlowId(p);
    double ts = nowSec();

    std::lock_guard<std::mutex> lk(mu_);
    flag_events_[flow_id].push_back(FlagEvent{ts, (uint8_t)has_syn, (uint8_t)has_fin, (uint8_t)has_rst});
    cleanupOldEventsLocked(flag_events_[flow_id], ts);

    if (has_syn) {
        std::string scan_key = dpid + "|tcp|" + p.src_ip + ":*->" + p.dst_ip + ":*";
        dst_port_seen_[scan_key][p.dst_port] = ts;
    }
}

GuardApp::ParsedPkt GuardApp::parseFrame(const uint8_t* data, size_t len) {
    ParsedPkt pkt;
    if (len < 14) return pkt;
    uint16_t ethertype = (uint16_t(data[12]) << 8) | data[13];
    size_t offset = 14;
    if (ethertype == 0x8100) {
        if (len < 18) return pkt;
        ethertype = (uint16_t(data[16]) << 8) | data[17];
        offset = 18;
    }
    if (ethertype != 0x0800) return pkt;
    if (len < offset + 20) return pkt;
    uint8_t ihl = (data[offset] & 0x0F) * 4;
    if (ihl < 20 || len < offset + ihl) return pkt;

    pkt.src_ip = ipToStr((uint32_t(data[offset + 12]) << 24) | (uint32_t(data[offset + 13]) << 16) | (uint32_t(data[offset + 14]) << 8) | data[offset + 15]);
    pkt.dst_ip = ipToStr((uint32_t(data[offset + 16]) << 24) | (uint32_t(data[offset + 17]) << 16) | (uint32_t(data[offset + 18]) << 8) | data[offset + 19]);

    if (data[offset + 9] == 6 && len >= offset + ihl + 20) {
        size_t tp = offset + ihl;
        pkt.is_tcp = true; pkt.valid = true;
        pkt.src_port = (uint16_t(data[tp]) << 8) | data[tp + 1];
        pkt.dst_port = (uint16_t(data[tp + 2]) << 8) | data[tp + 3];
        pkt.tcp_flags = data[tp + 13];
    }
    return pkt;
}

void GuardApp::pollFlowStats() {
    std::ifstream bfile("/tmp/guard_block.txt");
    if (bfile.is_open()) {
        std::string line;
        while (std::getline(bfile, line)) {
            if (!line.empty()) {
                try { installDropRule(parseFlowId(line)); } catch(...) {}
            }
        }
        bfile.close();
        std::ofstream clear_file("/tmp/guard_block.txt", std::ios::trunc);
    }

    double ts = nowSec();
    std::vector<json11::Json> items;

    std::lock_guard<std::mutex> lk(mu_);
    for (auto it = flag_events_.begin(); it != flag_events_.end(); ++it) {
        std::string flow_id = it->first;
        FlowRates fr = computeFlagRatesLocked(flow_id, ts);
        double udp = computeUniqueDstPortsLocked(flow_id, ts);

        if (fr.syn_rate == 0 && fr.fin_rate == 0 && fr.rst_rate == 0) continue;

        FlowIdParts p;
        try { p = parseFlowId(flow_id); } catch (...) { continue; }

        int syn_flood = (fr.syn_rate > syn_flood_rate_thr_) ? 1 : 0;
        int port_scan = (udp > port_scan_thr_) ? 1 : 0;

        items.push_back(json11::Json::object {
            {"ts", ts}, {"flow_id", flow_id}, {"src_ip", p.src_ip}, {"dst_ip", p.dst_ip},
            {"pps_in", 0.0}, {"bps_in", 0.0}, {"syn_rate", fr.syn_rate},
            {"fin_rate", fr.fin_rate}, {"rst_rate", fr.rst_rate},
            {"unique_dst_ports", udp}, {"avg_pkt_size", 0.0},
            {"runos_triggers", json11::Json::object {{"syn_flood", syn_flood}, {"port_scan", port_scan}}}
        });
    }

    json11::Json response = json11::Json::object { {"items", items} };
    std::ofstream sfile("/tmp/guard_stats.json");
    sfile << response.dump();
}

void GuardApp::installDropRule(const FlowIdParts& p) {
    uint64_t dpid_num = 0;
    try { dpid_num = std::stoull(p.dpid, nullptr, 16); } catch (...) { return; }
    
    if (connections_.find(dpid_num) == connections_.end()) return;
    OFConnectionPtr conn = connections_[dpid_num];

    fluid_msg::of13::FlowMod fm;
    fm.command(fluid_msg::of13::OFPFC_ADD);
    fm.table_id(drop_table_);
    fm.priority(drop_priority_);
    fm.idle_timeout(drop_idle_timeout_);
    fm.hard_timeout(0);

    fluid_msg::of13::EthType eth_type(0x0800);
    fm.add_oxm_field(eth_type);

    if (p.proto == "tcp") {
        fluid_msg::of13::IPProto proto(6); fm.add_oxm_field(proto);
        fluid_msg::of13::IPv4Src src_ip(p.src_ip); fm.add_oxm_field(src_ip);
        fluid_msg::of13::IPv4Dst dst_ip(p.dst_ip); fm.add_oxm_field(dst_ip);
        if (p.src_port) { fluid_msg::of13::TCPSrc sp(p.src_port); fm.add_oxm_field(sp); }
        if (p.dst_port) { fluid_msg::of13::TCPDst dp(p.dst_port); fm.add_oxm_field(dp); }
    }
    
    conn->send(fm);
    std::cout << "[GUARD] DROP RULE INSTALLED: " << p.src_ip << " -> " << p.dst_ip << std::endl;
}

void GuardApp::cleanupOldEventsLocked(std::deque<FlagEvent>& q, double now) {
    while (!q.empty() && (now - q.front().ts) > window_sec_) q.pop_front();
}

FlowRates GuardApp::computeFlagRatesLocked(const std::string& flow_id, double now) {
    FlowRates r;
    cleanupOldEventsLocked(flag_events_[flow_id], now);
    auto& q = flag_events_[flow_id];
    if (q.empty()) return r;

    double w = std::min(std::max(now - q.front().ts, 1.0), window_sec_);
    uint64_t syn = 0, fin = 0, rst = 0;
    for (auto& e : q) { syn += e.syn; fin += e.fin; rst += e.rst; }

    r.syn_rate = double(syn) / w; r.fin_rate = double(fin) / w; r.rst_rate = double(rst) / w;
    return r;
}

double GuardApp::computeUniqueDstPortsLocked(const std::string& flow_id, double now) {
    try {
        FlowIdParts p = parseFlowId(flow_id);
        auto it = dst_port_seen_.find(p.dpid + "|tcp|" + p.src_ip + ":*->" + p.dst_ip + ":*");
        if (it == dst_port_seen_.end()) return 1.0;

        double count = 0.0;
        for (auto& kv : it->second) if ((now - kv.second) <= window_sec_) count += 1.0;
        return std::max(count, 1.0);
    } catch (...) { return 1.0; }
}

FlowIdParts GuardApp::parseFlowId(const std::string& fid) {
    FlowIdParts p;
    auto a = fid.find('|'); auto b = fid.find('|', a + 1);
    p.dpid = fid.substr(0, a); p.proto = fid.substr(a + 1, b - (a + 1));
    std::string rest = fid.substr(b + 1);
    auto arrow = rest.find("->");
    std::string left = rest.substr(0, arrow), right = rest.substr(arrow + 2);
    auto c1 = left.rfind(':'), c2 = right.rfind(':');
    p.src_ip = left.substr(0, c1); p.dst_ip = right.substr(0, c2);
    p.src_port = std::stoi(left.substr(c1 + 1)); p.dst_port = std::stoi(right.substr(c2 + 1));
    return p;
}

std::string GuardApp::buildFlowId(const FlowIdParts& p) {
    return p.dpid + "|" + p.proto + "|" + p.src_ip + ":" + std::to_string(p.src_port) + "->" + p.dst_ip + ":" + std::to_string(p.dst_port);
}

} // namespace runos

