#ifndef NETWORK_ANALYZER_H
#define NETWORK_ANALYZER_H

#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <filesystem>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")

// 流量数据结构体
struct FlowData {
    std::string src_ip;
    std::string dst_ip;
    int protocol = 0;
    int src_port = 0;
    int dst_port = 0;
    long long data_size = 0;
    long long duration = 0;
};

// 节点统计信息结构体
struct NodeStats {
    long long total_sessions_as_src = 0;
    long long total_sessions_as_dst = 0;
    long long total_duration_as_src = 0;
    long long total_duration_as_dst = 0;
    long long total_out_data = 0;
    long long total_in_data = 0;

    long long get_total_sessions() const;
    long long get_total_duration() const;
    double get_src_session_ratio() const;
    long long get_total_data() const;
    double get_src_data_ratio() const;
};

// 边信息结构体
struct EdgeInfo {
    long long total_data_size = 0;
    long long total_duration = 0;
    std::unordered_map<int, std::pair<long long, long long>> proto_stats;

    double get_congestion() const;
};

// 路径结果结构体（新增：用于返回路径详情）
struct PathResult {
    std::vector<std::string> path_nodes;  // 路径节点列表
    double avg_congestion;                // 平均拥塞度
    int hop_count;                        // 跳数
    bool is_valid;                        // 是否有效
};

// 环结构检测结果（新增）
struct CycleResult {
    std::vector<std::vector<std::string>> cycles_3plus;  // 3+节点环
    std::vector<std::pair<std::string, std::string>> mutual_nodes;  // 互通节点（2节点环）
    std::vector<std::pair<std::string, std::string>> isolated_islands;  // 孤岛节点对
};

// 邻接节点结果（新增）
struct NeighborResult {
    std::vector<std::string> first_order;  // 一阶邻接节点
    std::vector<std::string> second_order; // 二阶邻接节点
    bool node_exists;                      // 节点是否存在
};

class NetworkAnalyzer {
private:
    std::vector<FlowData> flow_datas;
    std::unordered_map<std::string, NodeStats> node_stats;
    std::unordered_map<std::string, EdgeInfo> edge_stats;
    std::unordered_map<std::string, std::vector<std::pair<std::string, EdgeInfo>>> adj_graph;

    // 辅助函数
    std::vector<std::string> split(const std::string& s, char delimiter);
    void calc_node_bidirectional_flow();
    void build_adj_graph();
    bool is_boundary_node(const std::string& ip);
    bool is_sub_boundary_node(const std::string& ip);
    std::vector<std::pair<std::string, double>> filter_high_out_flow_nodes(double threshold);
    std::vector<std::string> filter_https_nodes();
    unsigned long ip_to_ulong(const std::string& ip);
    bool is_ip_in_range(const std::string& ip, const std::string& start_ip, const std::string& end_ip);

    // 环检测辅助函数（新增）
    void find_cycles_dfs(const std::string& start, const std::string& current, 
                         std::unordered_set<std::string>& visited, 
                         std::vector<std::string>& path,
                         std::unordered_set<std::string>& cycle_set,
                         std::vector<std::vector<std::string>>& all_cycles);
    bool is_isolated_island(const std::string& ip1, const std::string& ip2);  // 判断是否为孤岛

public:
    bool read_csv(const std::string& csv_path);
    void build_graph();

    // 路径查询（重构：返回结构化结果）
    PathResult find_shortest_hop_path(const std::string& start, const std::string& end);
    PathResult find_least_congestion_path(const std::string& start, const std::string& end);

    // 原有功能
    std::string get_star_structures_new(int min_connected = 20);
    std::vector<std::pair<std::string, long long>> sort_by_total_data();
    std::string get_sorted_by_data_result();
    std::string get_filtered_sorted_result_new(int filter_type, int sort_type);
    bool is_node_exist(const std::string& ip);
    std::string get_violation_nodes_result();
    std::string get_violation_sessions(const std::string& src_ip, const std::string& dst_start_ip, const std::string& dst_end_ip);

    // 新增功能：邻接节点查询（一阶/二阶）
    NeighborResult get_neighbors(const std::string& ip);

    // 新增功能：环结构检测
    CycleResult detect_cycles();
};

// DLL导出函数声明
#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

extern "C" {
    // 原有导出函数
    EXPORT NetworkAnalyzer* create_analyzer();
    EXPORT bool analyzer_read_csv(NetworkAnalyzer* analyzer, const char* csv_path);
    EXPORT void analyzer_build_graph(NetworkAnalyzer* analyzer);
    EXPORT bool analyzer_is_node_exist(NetworkAnalyzer* analyzer, const char* ip);
    EXPORT const char* analyzer_get_star_structures_new(NetworkAnalyzer* analyzer);
    EXPORT const char* analyzer_sort_by_data(NetworkAnalyzer* analyzer);
    EXPORT const char* analyzer_get_filtered_sorted_new(NetworkAnalyzer* analyzer, int filter_type, int sort_type);
    EXPORT const char* analyzer_get_violation_nodes(NetworkAnalyzer* analyzer);
    EXPORT const char* analyzer_get_violation_sessions(NetworkAnalyzer* analyzer, const char* src_ip, const char* dst_start_ip, const char* dst_end_ip);
    EXPORT void delete_analyzer(NetworkAnalyzer* analyzer);

    // 重构：路径查询（返回结构化数据）
    EXPORT int get_shortest_hop_path(NetworkAnalyzer* analyzer, const char* start, const char* end, 
                                     char* path_buf, double* avg_congestion, int buf_size);
    EXPORT int get_least_congestion_path(NetworkAnalyzer* analyzer, const char* start, const char* end, 
                                         char* path_buf, double* avg_congestion, int buf_size);

    // 新增：邻接节点查询
    EXPORT int get_neighbors(NetworkAnalyzer* analyzer, const char* ip, 
                             char* first_order_buf, char* second_order_buf, int buf_size);

    // 新增：环结构检测
    EXPORT const char* detect_cycles(NetworkAnalyzer* analyzer, bool filter_islands);
}

#endif // NETWORK_ANALYZER_H