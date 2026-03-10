#include "network_analyzer.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <string>
#include <algorithm>
#include <sstream>
#include <stdexcept>
#include <numeric>
#include <iomanip>
#include <queue>
#include <climits>
#include <cfloat>
#include <windows.h>
#include <filesystem>

// NodeStats 结构体成员函数实现
long long NodeStats::get_total_sessions() const { 
    return total_sessions_as_src + total_sessions_as_dst; 
}

long long NodeStats::get_total_duration() const { 
    return total_duration_as_src + total_duration_as_dst; 
}

double NodeStats::get_src_session_ratio() const {
    long long total = get_total_sessions();
    return total == 0 ? 0.0 : (double)total_sessions_as_src / total;
}

long long NodeStats::get_total_data() const { 
    return total_out_data + total_in_data; 
}

double NodeStats::get_src_data_ratio() const {
    long long total = get_total_data();
    return total == 0 ? 0.0 : (double)total_out_data / total;
}

// EdgeInfo 结构体成员函数实现
double EdgeInfo::get_congestion() const {
    if (total_duration == 0) return 0.0;
    return (double)total_data_size * 8 / total_duration; // 1字节=8比特
}

// NetworkAnalyzer 类成员函数实现
namespace {
    // 辅助函数：分割字符串（兼容空字段）
    std::vector<std::string> split(const std::string& s, char delimiter) {
        std::vector<std::string> tokens;
        std::string token;
        std::istringstream token_stream(s);
        while (std::getline(token_stream, token, delimiter)) {
            tokens.push_back(token);
        }
        // 补全空字段（确保至少7个字段）
        while (tokens.size() < 7) {
            tokens.push_back("");
        }
        return tokens;
    }
}

std::vector<std::string> NetworkAnalyzer::split(const std::string& s, char delimiter) {
    return ::split(s, delimiter);
}

// 新增：IP转无符号长整型
unsigned long NetworkAnalyzer::ip_to_ulong(const std::string& ip) {
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    
    unsigned long ip_addr = inet_addr(ip.c_str());
    WSACleanup();
    
    return ip_addr;
}

// 新增：判断IP是否在指定范围内
bool NetworkAnalyzer::is_ip_in_range(const std::string& ip, const std::string& start_ip, const std::string& end_ip) {
    try {
        unsigned long ip_ulong = ip_to_ulong(ip);
        unsigned long start_ulong = ip_to_ulong(start_ip);
        unsigned long end_ulong = ip_to_ulong(end_ip);
        
        // 处理大小端问题
        ip_ulong = ntohl(ip_ulong);
        start_ulong = ntohl(start_ulong);
        end_ulong = ntohl(end_ulong);
        
        return (ip_ulong >= start_ulong) && (ip_ulong <= end_ulong);
    } catch (...) {
        return false;
    }
}

bool NetworkAnalyzer::read_csv(const std::string& csv_path) {
    // Windows UTF-8路径兼容
    std::ifstream file;
    #ifdef _WIN32
    try {
        std::wstring wpath;
        int size = MultiByteToWideChar(CP_UTF8, 0, csv_path.c_str(), -1, NULL, 0);
        wpath.resize(size);
        MultiByteToWideChar(CP_UTF8, 0, csv_path.c_str(), -1, &wpath[0], size);
        
        std::filesystem::path fs_path(wpath);
        file.open(fs_path, std::ios::in);
    } catch (...) {
        file.open(csv_path, std::ios::in);
    }
    #else
    file.open(csv_path, std::ios::in);
    #endif

    if (!file.is_open()) {
        std::cerr << "Cannot open CSV file: " << csv_path << std::endl;
        return false;
    }

    flow_datas.clear();
    std::string line;
    int line_num = 0;
    int success_lines = 0;

    // 表头容错处理
    std::getline(file, line);
    line_num++;
    std::vector<std::string> header_fields = split(line, ',');
    bool has_header = (header_fields.size() >= 7 && 
                      (header_fields[0] == "src_ip" || header_fields[0] == "源IP"));
    if (!has_header) {
        file.seekg(0);
        line_num = 0;
    }

    while (std::getline(file, line)) {
        line_num++;
        std::vector<std::string> fields = split(line, ',');
        
        FlowData data;
        try {
            data.src_ip = fields[0].empty() ? "" : fields[0];
            data.dst_ip = fields[1].empty() ? "" : fields[1];
            data.protocol = fields[2].empty() ? 0 : std::stoi(fields[2]);
            data.src_port = fields[3].empty() ? 0 : std::stoi(fields[3]);
            data.dst_port = fields[4].empty() ? 0 : std::stoi(fields[4]);
            data.data_size = fields[5].empty() ? 0 : std::stoll(fields[5]);
            data.duration = fields[6].empty() ? 0 : std::stoll(fields[6]);

            if (!data.src_ip.empty() && !data.dst_ip.empty()) {
                flow_datas.push_back(data);
                success_lines++;
            }
        } catch (const std::exception& e) {
            std::cerr << "Line " << line_num << " parse error: " << e.what() << std::endl;
            continue;
        }
    }

    file.close();
    if (success_lines == 0) {
        std::cerr << "No valid flow data found" << std::endl;
        return false;
    }

    build_graph();
    return true;
}

void NetworkAnalyzer::calc_node_bidirectional_flow() {
    for (auto& node_pair : node_stats) {
        node_pair.second.total_in_data = 0;
    }
    for (const auto& edge_pair : edge_stats) {
        std::string edge_key = edge_pair.first;
        size_t sep = edge_key.find(':');
        if (sep == std::string::npos) continue;
        std::string dst_ip = edge_key.substr(sep + 1);
        node_stats[dst_ip].total_in_data += edge_pair.second.total_data_size;
    }
}

void NetworkAnalyzer::build_adj_graph() {
    adj_graph.clear();
    for (const auto& edge_pair : edge_stats) {
        std::string edge_key = edge_pair.first;
        size_t sep = edge_key.find(':');
        if (sep == std::string::npos) continue;
        std::string src = edge_key.substr(0, sep);
        std::string dst = edge_key.substr(sep + 1);
        adj_graph[src].emplace_back(dst, edge_pair.second);
        adj_graph[dst].emplace_back(src, edge_pair.second);
    }
}

bool NetworkAnalyzer::is_boundary_node(const std::string& ip) {
    if (!adj_graph.count(ip)) return true;
    return adj_graph[ip].size() == 0;
}

bool NetworkAnalyzer::is_sub_boundary_node(const std::string& ip) {
    if (!adj_graph.count(ip) || adj_graph[ip].size() == 0) return false;
    for (const auto& neighbor : adj_graph[ip]) {
        if (!is_boundary_node(neighbor.first)) {
            return false;
        }
    }
    return true;
}

void NetworkAnalyzer::build_graph() {
    node_stats.clear();
    edge_stats.clear();

    for (const auto& flow : flow_datas) {
        std::string src_ip = flow.src_ip;
        std::string dst_ip = flow.dst_ip;

        // 节点统计
        node_stats[src_ip].total_sessions_as_src += 1;
        node_stats[src_ip].total_duration_as_src += flow.duration;
        node_stats[src_ip].total_out_data += flow.data_size;

        node_stats[dst_ip].total_sessions_as_dst += 1;
        node_stats[dst_ip].total_duration_as_dst += flow.duration;

        // 边统计
        std::string edge_key = src_ip + ":" + dst_ip;
        EdgeInfo& edge = edge_stats[edge_key];
        edge.total_data_size += flow.data_size;
        edge.total_duration += flow.duration;
        auto& proto_stat = edge.proto_stats[flow.protocol];
        proto_stat.first += flow.data_size;
        proto_stat.second += flow.duration;
    }

    calc_node_bidirectional_flow();
    build_adj_graph();
}

std::pair<std::vector<std::string>, double> NetworkAnalyzer::find_shortest_hop_path(const std::string& start, const std::string& end) {
    if (!node_stats.count(start) || !node_stats.count(end)) {
        return {{}, -1.0};
    }
    if (start == end) {
        return {{start}, 0.0};
    }

    std::unordered_map<std::string, std::string> parent;
    std::queue<std::string> q;
    std::unordered_set<std::string> visited;

    q.push(start);
    visited.insert(start);
    bool found = false;

    while (!q.empty() && !found) {
        std::string curr = q.front();
        q.pop();

        if (!adj_graph.count(curr)) continue;
        for (const auto& neighbor : adj_graph[curr]) {
            const std::string& next = neighbor.first;
            if (!visited.count(next)) {
                parent[next] = curr;
                visited.insert(next);
                q.push(next);
                if (next == end) {
                    found = true;
                    break;
                }
            }
        }
    }

    if (!found) {
        return {{}, -2.0};
    }

    std::vector<std::string> path;
    for (std::string curr = end; curr != start; curr = parent[curr]) {
        path.push_back(curr);
    }
    path.push_back(start);
    std::reverse(path.begin(), path.end());

    double total_congestion = 0.0;
    for (size_t i = 0; i < path.size() - 1; i++) {
        std::string edge_key = path[i] + ":" + path[i+1];
        if (edge_stats.count(edge_key)) {
            total_congestion += edge_stats[edge_key].get_congestion();
        } else {
            edge_key = path[i+1] + ":" + path[i];
            total_congestion += edge_stats[edge_key].get_congestion();
        }
    }
    double avg_congestion = total_congestion / (path.size() - 1);

    return {path, avg_congestion};
}

std::pair<std::vector<std::string>, double> NetworkAnalyzer::find_least_congestion_path(const std::string& start, const std::string& end) {
    if (!node_stats.count(start) || !node_stats.count(end)) {
        return {{}, -1.0};
    }
    if (start == end) {
        return {{start}, 0.0};
    }

    std::unordered_map<std::string, double> dist;
    std::unordered_map<std::string, std::string> parent;
    std::priority_queue<std::pair<double, std::string>, 
                        std::vector<std::pair<double, std::string>>,
                        std::greater<std::pair<double, std::string>>> pq;

    for (const auto& node : node_stats) {
        dist[node.first] = DBL_MAX;
    }
    dist[start] = 0.0;
    pq.push({0.0, start});

    while (!pq.empty()) {
        auto [curr_dist, curr] = pq.top();
        pq.pop();

        if (curr == end) break;
        if (curr_dist > dist[curr]) continue;

        if (!adj_graph.count(curr)) continue;
        for (const auto& neighbor : adj_graph[curr]) {
            const std::string& next = neighbor.first;
            double edge_congestion = neighbor.second.get_congestion();
            double new_dist = curr_dist + edge_congestion;

            if (new_dist < dist[next]) {
                dist[next] = new_dist;
                parent[next] = curr;
                pq.push({new_dist, next});
            }
        }
    }

    if (dist[end] == DBL_MAX) {
        return {{}, -2.0};
    }

    std::vector<std::string> path;
    for (std::string curr = end; curr != start; curr = parent[curr]) {
        path.push_back(curr);
    }
    path.push_back(start);
    std::reverse(path.begin(), path.end());

    double avg_congestion = dist[end] / (path.size() - 1);
    return {path, avg_congestion};
}

// 修改：星型节点检测简化规则 - 仅判断相邻节点数≥20
std::string NetworkAnalyzer::get_star_structures_new(int min_connected) {
    std::ostringstream oss;
    int star_count = 0;

    for (const auto& node_pair : node_stats) {
        const std::string& center = node_pair.first;
        if (!adj_graph.count(center)) continue;

        // 统计所有相连节点
        std::vector<std::string> all_neighbors;
        for (const auto& neighbor : adj_graph[center]) {
            all_neighbors.push_back(neighbor.first);
        }

        // 简化规则：仅判断相邻节点数≥20
        if (all_neighbors.size() >= min_connected) {
            star_count++;
            oss << "⭐ 星型中心节点：" << center << "\n";
            oss << "总相连节点数：" << all_neighbors.size() << "\n";
            oss << "关联节点列表：\n";
            for (size_t i = 0; i < all_neighbors.size(); i++) {
                oss << all_neighbors[i];
                if (i != all_neighbors.size() - 1) {
                    oss << ",";
                }
                oss << "\n";
            }
            oss << "--------------------------------------------------------\n";
        }
    }

    if (star_count == 0) {
        oss << "未检测到符合规则的星型结构节点（相邻节点数≥20）\n";
    }
    return oss.str();
}

std::vector<std::pair<std::string, long long>> NetworkAnalyzer::sort_by_total_data() {
    std::vector<std::pair<std::string, long long>> result;
    for (const auto& pair : node_stats) {
        long long total_data = pair.second.get_total_data();
        if (total_data > 0) {
            result.emplace_back(pair.first, total_data);
        }
    }
    std::sort(result.begin(), result.end(), [](const auto& a, const auto& b) {
        return a.second > b.second;
    });
    return result;
}

std::string NetworkAnalyzer::get_sorted_by_data_result() {
    auto sorted_data = sort_by_total_data();
    std::ostringstream oss;
    oss << std::left 
        << std::setw(18) << "节点IP" 
        << std::setw(20) << "作为源的总流量（字节）" 
        << std::setw(20) << "作为目的的总流量（字节）" 
        << std::setw(20) << "全部流量（字节）"
        << std::setw(15) << "源流量占比（%）\n";
    oss << "------------------------------------------------------------------------------------------------------------------------\n";

    for (const auto& pair : sorted_data) {
        const auto& stats = node_stats[pair.first];
        double ratio = stats.get_src_data_ratio() * 100;
        oss << std::left 
            << std::setw(18) << pair.first 
            << std::setw(20) << stats.total_out_data 
            << std::setw(20) << stats.total_in_data 
            << std::setw(20) << pair.second
            << std::setw(15) << std::fixed << std::setprecision(2) << ratio << "\n";
    }
    if (sorted_data.empty()) {
        oss << "暂无流量数据\n";
    }
    return oss.str();
}

std::vector<std::pair<std::string, double>> NetworkAnalyzer::filter_high_out_flow_nodes(double threshold) {
    std::vector<std::pair<std::string, double>> result;
    for (const auto& node_pair : node_stats) {
        double ratio = node_pair.second.get_src_data_ratio();
        if (ratio > threshold) {
            result.emplace_back(node_pair.first, ratio);
        }
    }
    std::sort(result.begin(), result.end(), [](const auto& a, const auto& b) {
        return a.second > b.second;
    });
    return result;
}

std::vector<std::string> NetworkAnalyzer::filter_https_nodes() {
    std::unordered_set<std::string> https_ips;
    for (const auto& flow : flow_datas) {
        if (flow.protocol == 6 && (flow.src_port == 443 || flow.dst_port == 443)) {
            https_ips.insert(flow.src_ip);
            https_ips.insert(flow.dst_ip);
        }
    }
    return std::vector<std::string>(https_ips.begin(), https_ips.end());
}

std::string NetworkAnalyzer::get_filtered_sorted_result_new(int filter_type, int sort_type) {
    std::unordered_set<std::string> filtered_ips;
    std::string filter_desc;

    if (filter_type == 0) {
        filter_desc = "无筛选";
        for (const auto& node_pair : node_stats) {
            filtered_ips.insert(node_pair.first);
        }
    } else if (filter_type == 1) {
        filter_desc = "单向流量>80%节点（按data_size）";
        auto high_flow_nodes = filter_high_out_flow_nodes(0.8);
        for (const auto& pair : high_flow_nodes) {
            filtered_ips.insert(pair.first);
        }
    } else if (filter_type == 2) {
        filter_desc = "HTTPS节点";
        auto https_ips = filter_https_nodes();
        filtered_ips = std::unordered_set<std::string>(https_ips.begin(), https_ips.end());
    }

    std::vector<std::pair<std::string, long long>> sorted_data;
    std::string sort_desc;
    std::ostringstream header_oss;

    if (sort_type == 0) {
        sort_desc = "总会话数";
        header_oss << std::left 
                   << std::setw(18) << "节点IP" 
                   << std::setw(15) << "源会话数" 
                   << std::setw(15) << "目的会话数" 
                   << std::setw(10) << "总会话数"
                   << std::setw(15) << "源流量占比（%）\n";
        for (const auto& ip : filtered_ips) {
            long long total = node_stats[ip].get_total_sessions();
            if (total > 0) {
                sorted_data.emplace_back(ip, total);
            }
        }
        std::sort(sorted_data.begin(), sorted_data.end(), [](const auto& a, const auto& b) {
            return a.second > b.second;
        });
    } else if (sort_type == 1) {
        sort_desc = "总时长";
        header_oss << std::left 
                   << std::setw(18) << "节点IP" 
                   << std::setw(20) << "总时长（秒）"
                   << std::setw(15) << "源流量占比（%）\n";
        for (const auto& ip : filtered_ips) {
            long long total = node_stats[ip].get_total_duration();
            if (total > 0) {
                sorted_data.emplace_back(ip, total);
            }
        }
        std::sort(sorted_data.begin(), sorted_data.end(), [](const auto& a, const auto& b) {
            return a.second > b.second;
        });
    } else if (sort_type == 2) {
        sort_desc = "总流量";
        header_oss << std::left 
                   << std::setw(18) << "节点IP" 
                   << std::setw(20) << "源总流量（字节）" 
                   << std::setw(20) << "目的总流量（字节）" 
                   << std::setw(20) << "总流量（字节）"
                   << std::setw(15) << "源流量占比（%）\n";
        for (const auto& ip : filtered_ips) {
            long long total = node_stats[ip].get_total_data();
            if (total > 0) {
                sorted_data.emplace_back(ip, total);
            }
        }
        std::sort(sorted_data.begin(), sorted_data.end(), [](const auto& a, const auto& b) {
            return a.second > b.second;
        });
    }

    std::ostringstream oss;
    oss << "筛选条件：" << filter_desc << " | 排序方式：" << sort_desc << "\n";
    oss << "------------------------------------------------------------------------------------------------------------------------\n";
    oss << header_oss.str();
    oss << "------------------------------------------------------------------------------------------------------------------------\n";

    if (sort_type == 0) {
        for (const auto& pair : sorted_data) {
            const auto& stats = node_stats[pair.first];
            double ratio = stats.get_src_data_ratio() * 100;
            oss << std::left 
                << std::setw(18) << pair.first 
                << std::setw(15) << stats.total_sessions_as_src 
                << std::setw(15) << stats.total_sessions_as_dst 
                << std::setw(10) << pair.second
                << std::setw(15) << std::fixed << std::setprecision(2) << ratio << "\n";
        }
    } else if (sort_type == 1) {
        for (const auto& pair : sorted_data) {
            const auto& stats = node_stats[pair.first];
            double ratio = stats.get_src_data_ratio() * 100;
            oss << std::left 
                << std::setw(18) << pair.first 
                << std::setw(20) << pair.second
                << std::setw(15) << std::fixed << std::setprecision(2) << ratio << "\n";
        }
    } else if (sort_type == 2) {
        for (const auto& pair : sorted_data) {
            const auto& stats = node_stats[pair.first];
            double ratio = stats.get_src_data_ratio() * 100;
            oss << std::left 
                << std::setw(18) << pair.first 
                << std::setw(20) << stats.total_out_data 
                << std::setw(20) << stats.total_in_data 
                << std::setw(20) << pair.second
                << std::setw(15) << std::fixed << std::setprecision(2) << ratio << "\n";
        }
    }

    if (sorted_data.empty()) {
        oss << "暂无符合条件的数据\n";
    }
    return oss.str();
}

std::string NetworkAnalyzer::get_violation_nodes_result() {
    std::ostringstream oss;
    std::vector<std::pair<std::string, NodeStats>> violation_nodes;

    for (const auto& node_pair : node_stats) {
        const auto& ip = node_pair.first;
        const auto& stats = node_pair.second;
        
        double src_data_ratio = stats.get_src_data_ratio();
        long long src_sessions = stats.total_sessions_as_src;

        // 判定条件：源流量占比>90% 且 源会话数>3
        if (src_data_ratio > 0.9 && src_sessions > 3) {
            violation_nodes.emplace_back(ip, stats);
        }
    }

    // 按源流量占比降序排序
    std::sort(violation_nodes.begin(), violation_nodes.end(), [](const auto& a, const auto& b) {
        return a.second.get_src_data_ratio() > b.second.get_src_data_ratio();
    });

    // 格式化输出
    oss << "🚨 违规节点检测结果（源流量占比>90% 且 源会话数>3）\n";
    oss << "------------------------------------------------------------------------------------------------------------------------\n";
    oss << std::left 
        << std::setw(18) << "节点IP" 
        << std::setw(20) << "源流量（字节）" 
        << std::setw(20) << "目的流量（字节）" 
        << std::setw(15) << "源流量占比（%）"
        << std::setw(15) << "源会话数\n";
    oss << "------------------------------------------------------------------------------------------------------------------------\n";

    if (violation_nodes.empty()) {
        oss << "未检测到违规节点\n";
    } else {
        for (const auto& pair : violation_nodes) {
            const auto& ip = pair.first;
            const auto& stats = pair.second;
            double ratio = stats.get_src_data_ratio() * 100;
            
            oss << std::left 
                << std::setw(18) << ip 
                << std::setw(20) << stats.total_out_data 
                << std::setw(20) << stats.total_in_data 
                << std::setw(15) << std::fixed << std::setprecision(2) << ratio
                << std::setw(15) << stats.total_sessions_as_src << "\n";
        }
    }

    return oss.str();
}

// 新增：违规会话检测实现
std::string NetworkAnalyzer::get_violation_sessions(const std::string& src_ip, const std::string& dst_start_ip, const std::string& dst_end_ip) {
    std::ostringstream oss;
    std::vector<FlowData> violation_flows;

    // 筛选符合条件的会话
    for (const auto& flow : flow_datas) {
        // 源IP匹配 + 目的IP在指定范围
        if (flow.src_ip == src_ip && is_ip_in_range(flow.dst_ip, dst_start_ip, dst_end_ip)) {
            violation_flows.push_back(flow);
        }
    }

    // 格式化输出
    oss << "🚨 违规会话检测结果\n";
    oss << "筛选条件：源IP=" << src_ip << " | 目的IP范围=[" << dst_start_ip << ", " << dst_end_ip << "]\n";
    oss << "------------------------------------------------------------------------------------------------------------------------\n";
    oss << std::left 
        << std::setw(18) << "源IP" 
        << std::setw(18) << "目的IP" 
        << std::setw(10) << "协议" 
        << std::setw(10) << "源端口" 
        << std::setw(10) << "目的端口" 
        << std::setw(20) << "数据大小（字节）" 
        << std::setw(15) << "时长（秒）\n";
    oss << "------------------------------------------------------------------------------------------------------------------------\n";

    if (violation_flows.empty()) {
        oss << "未检测到符合条件的违规会话\n";
    } else {
        for (const auto& flow : violation_flows) {
            oss << std::left 
                << std::setw(18) << flow.src_ip 
                << std::setw(18) << flow.dst_ip 
                << std::setw(10) << flow.protocol 
                << std::setw(10) << flow.src_port 
                << std::setw(10) << flow.dst_port 
                << std::setw(20) << flow.data_size 
                << std::setw(15) << flow.duration << "\n";
        }
        oss << "\n总计违规会话数：" << violation_flows.size() << "\n";
    }

    return oss.str();
}

bool NetworkAnalyzer::is_node_exist(const std::string& ip) {
    return node_stats.count(ip) > 0;
}

// DLL导出函数实现
extern "C" {
    __declspec(dllexport) NetworkAnalyzer* create_analyzer() {
        return new NetworkAnalyzer();
    }

    __declspec(dllexport) bool analyzer_read_csv(NetworkAnalyzer* analyzer, const char* csv_path) {
        if (!analyzer) return false;
        return analyzer->read_csv(std::string(csv_path));
    }

    __declspec(dllexport) void analyzer_build_graph(NetworkAnalyzer* analyzer) {
        if (analyzer) analyzer->build_graph();
    }

    __declspec(dllexport) int find_shortest_hop_path(NetworkAnalyzer* analyzer, const char* start, const char* end, char* path_buf, double* avg_congestion, int buf_size) {
        if (!analyzer) return -1;
        auto [path, congestion] = analyzer->find_shortest_hop_path(std::string(start), std::string(end));
        if (path.empty()) {
            *avg_congestion = congestion;
            return (int)congestion;
        }
        std::string path_str;
        for (size_t i = 0; i < path.size(); i++) {
            path_str += path[i];
            if (i != path.size() - 1) {
                path_str += " -> ";
            }
        }
        strncpy(path_buf, path_str.c_str(), buf_size - 1);
        path_buf[buf_size - 1] = '\0';
        *avg_congestion = congestion;
        return (int)path.size() - 1;
    }

    __declspec(dllexport) int find_least_congestion_path(NetworkAnalyzer* analyzer, const char* start, const char* end, char* path_buf, double* avg_congestion, int buf_size) {
        if (!analyzer) return -1;
        auto [path, congestion] = analyzer->find_least_congestion_path(std::string(start), std::string(end));
        if (path.empty()) {
            *avg_congestion = congestion;
            return (int)congestion;
        }
        std::string path_str;
        for (size_t i = 0; i < path.size(); i++) {
            path_str += path[i];
            if (i != path.size() - 1) {
                path_str += " -> ";
            }
        }
        strncpy(path_buf, path_str.c_str(), buf_size - 1);
        path_buf[buf_size - 1] = '\0';
        *avg_congestion = congestion;
        return (int)path.size() - 1;
    }

    __declspec(dllexport) const char* analyzer_get_star_structures_new(NetworkAnalyzer* analyzer) {
        static std::string result;
        if (analyzer) {
            result = analyzer->get_star_structures_new();
        } else {
            result = "Analyzer instance is null";
        }
        return result.c_str();
    }

    __declspec(dllexport) const char* analyzer_sort_by_data(NetworkAnalyzer* analyzer) {
        static std::string result;
        if (analyzer) {
            result = analyzer->get_sorted_by_data_result();
        } else {
            result = "Analyzer instance is null";
        }
        return result.c_str();
    }

    __declspec(dllexport) const char* analyzer_get_filtered_sorted_new(NetworkAnalyzer* analyzer, int filter_type, int sort_type) {
        static std::string result;
        if (analyzer) {
            result = analyzer->get_filtered_sorted_result_new(filter_type, sort_type);
        } else {
            result = "Analyzer instance is null";
        }
        return result.c_str();
    }

    __declspec(dllexport) bool analyzer_is_node_exist(NetworkAnalyzer* analyzer, const char* ip) {
        if (!analyzer) return false;
        return analyzer->is_node_exist(std::string(ip));
    }

    __declspec(dllexport) const char* analyzer_get_violation_nodes(NetworkAnalyzer* analyzer) {
        static std::string result;
        if (analyzer) {
            result = analyzer->get_violation_nodes_result();
        } else {
            result = "Analyzer instance is null";
        }
        return result.c_str();
    }

    // 新增：违规会话检测导出函数
    __declspec(dllexport) const char* analyzer_get_violation_sessions(NetworkAnalyzer* analyzer, const char* src_ip, const char* dst_start_ip, const char* dst_end_ip) {
        static std::string result;
        if (analyzer) {
            result = analyzer->get_violation_sessions(std::string(src_ip), std::string(dst_start_ip), std::string(dst_end_ip));
        } else {
            result = "Analyzer instance is null";
        }
        return result.c_str();
    }

    __declspec(dllexport) void delete_analyzer(NetworkAnalyzer* analyzer) {
        if (analyzer) delete analyzer;
    }
}