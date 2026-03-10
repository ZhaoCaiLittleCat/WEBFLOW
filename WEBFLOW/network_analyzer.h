#ifndef NETWORK_ANALYZER_H
#define NETWORK_ANALYZER_H

#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <filesystem>
// 引入winsock2.h处理IP地址
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")

// 流量数据结构体（兼容空字段）
struct FlowData {
    std::string src_ip;
    std::string dst_ip;
    int protocol = 0;
    int src_port = 0;
    int dst_port = 0;
    long long data_size = 0;
    long long duration = 0;
};

// 节点统计信息结构体（新增总流量字段）
struct NodeStats {
    long long total_sessions_as_src = 0;
    long long total_sessions_as_dst = 0;
    long long total_duration_as_src = 0;
    long long total_duration_as_dst = 0;
    long long total_out_data = 0;  // 作为源的总流量（字节）
    long long total_in_data = 0;   // 作为目的的总流量（字节）

    // 总会话数
    long long get_total_sessions() const;
    // 总时长
    long long get_total_duration() const;
    // 源会话数占比
    double get_src_session_ratio() const;
    // 总流量（源+目的）
    long long get_total_data() const;
    // 源流量占总流量的比例
    double get_src_data_ratio() const;
};

// 边信息结构体（新增拥塞程度计算）
struct EdgeInfo {
    long long total_data_size = 0;
    long long total_duration = 0;
    std::unordered_map<int, std::pair<long long, long long>> proto_stats; // <协议, <数据量, 时长>>

    // 计算拥塞程度（单位：bps，比特/秒）
    double get_congestion() const;
};

class NetworkAnalyzer {
private:
    // 原始流量数据
    std::vector<FlowData> flow_datas;
    // 节点统计信息 <IP, 统计数据>
    std::unordered_map<std::string, NodeStats> node_stats;
    // 边统计信息 <src:dst, 边数据>
    std::unordered_map<std::string, EdgeInfo> edge_stats;
    // 邻接图（寻路算法用）<源IP, <目的IP, 边信息>>
    std::unordered_map<std::string, std::vector<std::pair<std::string, EdgeInfo>>> adj_graph;

    // 辅助函数：分割字符串（兼容空字段，补全至7个）
    std::vector<std::string> split(const std::string& s, char delimiter);

    // 计算节点双向流量（更新入站流量）
    void calc_node_bidirectional_flow();

    // 构建邻接图（寻路算法基础）
    void build_adj_graph();

    // 判断是否为边界节点（无下一跳）
    bool is_boundary_node(const std::string& ip);

    // 判断是否为次边界节点（下一跳均为边界节点）
    bool is_sub_boundary_node(const std::string& ip);

    // 筛选单向流量>阈值的节点（内部辅助）
    std::vector<std::pair<std::string, double>> filter_high_out_flow_nodes(double threshold);

    // 筛选HTTPS节点（内部辅助）
    std::vector<std::string> filter_https_nodes();

    // 辅助函数：将IP字符串转换为无符号长整型
    unsigned long ip_to_ulong(const std::string& ip);
    
    // 辅助函数：判断IP是否在指定范围内
    bool is_ip_in_range(const std::string& ip, const std::string& start_ip, const std::string& end_ip);

public:
    // 读取CSV（容错解析：字段数≠7也可统计，空字段赋默认值）
    bool read_csv(const std::string& csv_path);

    // 构建图（节点/边统计 + 邻接图）
    void build_graph();

    // 寻路算法1：跳数最小路径（BFS）
    std::pair<std::vector<std::string>, double> find_shortest_hop_path(const std::string& start, const std::string& end);

    // 寻路算法2：拥塞程度最小路径（Dijkstra）
    std::pair<std::vector<std::string>, double> find_least_congestion_path(const std::string& start, const std::string& end);

    // 星型节点检测：简化规则 - 关联≥20个节点即算
    std::string get_star_structures_new(int min_connected = 20);

    // 按总流量排序（源+目的）
    std::vector<std::pair<std::string, long long>> sort_by_total_data();

    // 按流量排序的格式化输出（带表头，列对齐，新增源流量占比列）
    std::string get_sorted_by_data_result();

    // 通用筛选+排序（嵌套逻辑：先筛选后排序）
    // filter_type：0=无筛选，1=单向流量>80%（按data_size），2=HTTPS节点
    // sort_type：0=会话数，1=时长，2=流量
    std::string get_filtered_sorted_result_new(int filter_type, int sort_type);

    // 检查节点是否存在（用于GUI输入校验）
    bool is_node_exist(const std::string& ip);

    // 违规节点检测：单向流量占比>90% 且 源会话数>3
    std::string get_violation_nodes_result();

    // 新增：违规会话检测 - 源IP固定，目的IP在指定范围
    std::string get_violation_sessions(const std::string& src_ip, const std::string& dst_start_ip, const std::string& dst_end_ip);
};

// DLL导出函数声明（extern "C"避免命名修饰）
#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

extern "C" {
    // 创建分析器实例
    EXPORT NetworkAnalyzer* create_analyzer();

    // 读取CSV文件
    EXPORT bool analyzer_read_csv(NetworkAnalyzer* analyzer, const char* csv_path);

    // 构建图（内部调用，可省略）
    EXPORT void analyzer_build_graph(NetworkAnalyzer* analyzer);

    // 查找跳数最小路径
    EXPORT int find_shortest_hop_path(NetworkAnalyzer* analyzer, const char* start, const char* end, char* path_buf, double* avg_congestion, int buf_size);

    // 查找拥塞程度最小路径（参数/返回值同跳数最小）
    EXPORT int find_least_congestion_path(NetworkAnalyzer* analyzer, const char* start, const char* end, char* path_buf, double* avg_congestion, int buf_size);

    // 星型节点检测（简化规则）
    EXPORT const char* analyzer_get_star_structures_new(NetworkAnalyzer* analyzer);

    // 按流量排序（格式化输出）
    EXPORT const char* analyzer_sort_by_data(NetworkAnalyzer* analyzer);

    // 通用筛选+排序（新逻辑）
    EXPORT const char* analyzer_get_filtered_sorted_new(NetworkAnalyzer* analyzer, int filter_type, int sort_type);

    // 检查节点是否存在
    EXPORT bool analyzer_is_node_exist(NetworkAnalyzer* analyzer, const char* ip);

    // 违规节点检测
    EXPORT const char* analyzer_get_violation_nodes(NetworkAnalyzer* analyzer);

    // 新增：违规会话检测
    EXPORT const char* analyzer_get_violation_sessions(NetworkAnalyzer* analyzer, const char* src_ip, const char* dst_start_ip, const char* dst_end_ip);

    // 释放分析器实例
    EXPORT void delete_analyzer(NetworkAnalyzer* analyzer);
}

#endif // NETWORK_ANALYZER_H