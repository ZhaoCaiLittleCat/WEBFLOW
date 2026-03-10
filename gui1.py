import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
import ctypes
import os
import sys
import networkx as nx
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import warnings
warnings.filterwarnings("ignore")

# 设置matplotlib中文显示
plt.rcParams["font.family"] = ["SimHei", "WenQuanYi Micro Hei", "Heiti TC"]
plt.rcParams["axes.unicode_minus"] = False

# DLL调用封装
class NetworkAnalyzerDLL:
    def __init__(self):
        self.dll = None
        self.analyzer = None
        try:
            dll_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "network_analyzer.dll")
            if not os.path.exists(dll_path):
                dll_path = "network_analyzer.dll"
            
            self.dll = ctypes.CDLL(dll_path, winmode=0)
            
            # 函数类型定义
            self.dll.create_analyzer.restype = ctypes.c_void_p
            self.dll.create_analyzer.argtypes = []
            
            self.dll.analyzer_read_csv.restype = ctypes.c_bool
            self.dll.analyzer_read_csv.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
            
            # 路径查询（重构）
            self.dll.get_shortest_hop_path.restype = ctypes.c_int
            self.dll.get_shortest_hop_path.argtypes = [
                ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p,
                ctypes.c_char_p, ctypes.POINTER(ctypes.c_double), ctypes.c_int
            ]
            
            self.dll.get_least_congestion_path.restype = ctypes.c_int
            self.dll.get_least_congestion_path.argtypes = [
                ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p,
                ctypes.c_char_p, ctypes.POINTER(ctypes.c_double), ctypes.c_int
            ]
            
            # 星型节点
            self.dll.analyzer_get_star_structures_new.restype = ctypes.c_char_p
            self.dll.analyzer_get_star_structures_new.argtypes = [ctypes.c_void_p]
            
            # 流量排序
            self.dll.analyzer_sort_by_data.restype = ctypes.c_char_p
            self.dll.analyzer_sort_by_data.argtypes = [ctypes.c_void_p]
            
            # 筛选+排序
            self.dll.analyzer_get_filtered_sorted_new.restype = ctypes.c_char_p
            self.dll.analyzer_get_filtered_sorted_new.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int]
            
            # 违规节点
            self.dll.analyzer_get_violation_nodes.restype = ctypes.c_char_p
            self.dll.analyzer_get_violation_nodes.argtypes = [ctypes.c_void_p]
            
            # 违规会话
            self.dll.analyzer_get_violation_sessions.restype = ctypes.c_char_p
            self.dll.analyzer_get_violation_sessions.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
            
            # 节点存在性
            self.dll.analyzer_is_node_exist.restype = ctypes.c_bool
            self.dll.analyzer_is_node_exist.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
            
            # 新增：邻接节点查询
            self.dll.get_neighbors.restype = ctypes.c_int
            self.dll.get_neighbors.argtypes = [ctypes.c_void_p, ctypes.c_char_p,
                                               ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
            
            # 新增：环检测
            self.dll.detect_cycles.restype = ctypes.c_char_p
            self.dll.detect_cycles.argtypes = [ctypes.c_void_p, ctypes.c_bool]
            
            # 删除实例
            self.dll.delete_analyzer.restype = None
            self.dll.delete_analyzer.argtypes = [ctypes.c_void_p]
            
            # 创建实例
            self.analyzer = self.dll.create_analyzer()
            if not self.analyzer:
                raise RuntimeError("创建分析器实例失败")
                
        except FileNotFoundError:
            raise RuntimeError(f"DLL文件不存在：{dll_path}")
        except AttributeError as e:
            raise RuntimeError(f"找不到指定函数：{str(e)}\n请检查DLL编译是否正确")
        except Exception as e:
            raise RuntimeError(f"DLL加载失败：{str(e)}")
    
    def __del__(self):
        if self.dll and self.analyzer:
            try:
                self.dll.delete_analyzer(self.analyzer)
            except:
                pass
    
    def read_csv(self, csv_path):
        try:
            if sys.platform == "win32":
                csv_path_encoded = csv_path.encode("gbk")
            else:
                csv_path_encoded = csv_path.encode("utf-8")
            result = self.dll.analyzer_read_csv(self.analyzer, csv_path_encoded)
            if not result:
                messagebox.showwarning("读取失败", "CSV文件读取失败，请检查文件格式")
                return False
            messagebox.showinfo("成功", "CSV文件读取并解析完成！")
            return True
        except Exception as e:
            messagebox.showerror("读取CSV失败", f"错误：{str(e)}")
            return False
    
    def find_paths(self, start_ip, end_ip):
        """获取两条路径并返回结构化数据（用于可视化）"""
        try:
            if not self.dll.analyzer_is_node_exist(self.analyzer, start_ip.encode("utf-8")):
                return {"success": False, "msg": f"错误：源节点 {start_ip} 不存在！"}
            if not self.dll.analyzer_is_node_exist(self.analyzer, end_ip.encode("utf-8")):
                return {"success": False, "msg": f"错误：目的节点 {end_ip} 不存在！"}
            
            buf_size = 1024
            path_buf = ctypes.create_string_buffer(buf_size)
            avg_congestion = ctypes.c_double(0.0)
            
            # 跳数最小路径
            hop_count = self.dll.get_shortest_hop_path(
                self.analyzer, start_ip.encode("utf-8"), end_ip.encode("utf-8"),
                path_buf, ctypes.byref(avg_congestion), buf_size
            )
            if hop_count == -1:
                return {"success": False, "msg": f"错误：{start_ip} 和 {end_ip} 之间无连通路径！"}
            shortest_hop_path_str = path_buf.value.decode("utf-8")
            shortest_hop_path = shortest_hop_path_str.split(" -> ")
            shortest_hop_congestion = avg_congestion.value
            
            # 拥塞最小路径
            congestion_hop_count = self.dll.get_least_congestion_path(
                self.analyzer, start_ip.encode("utf-8"), end_ip.encode("utf-8"),
                path_buf, ctypes.byref(avg_congestion), buf_size
            )
            least_congestion_path_str = path_buf.value.decode("utf-8")
            least_congestion_path = least_congestion_path_str.split(" -> ")
            least_congestion_value = avg_congestion.value
            
            # 构建结果文本
            result_text = f"📌 跳数最小路径：\n{shortest_hop_path_str}\n"
            result_text += f"跳数：{hop_count} | 平均拥塞程度：{shortest_hop_congestion:.2f} bps\n\n"
            result_text += f"📌 拥塞程度最小路径：\n{least_congestion_path_str}\n"
            result_text += f"跳数：{congestion_hop_count} | 平均拥塞程度：{least_congestion_value:.2f} bps"
            
            return {
                "success": True,
                "msg": result_text,
                "shortest_hop_path": shortest_hop_path,
                "least_congestion_path": least_congestion_path,
                "start_ip": start_ip,
                "end_ip": end_ip
            }
        except Exception as e:
            return {"success": False, "msg": f"寻路失败：{str(e)}"}
    
    def get_star_structures_new(self):
        try:
            result_ptr = self.dll.analyzer_get_star_structures_new(self.analyzer)
            if result_ptr:
                return result_ptr.decode("utf-8")
            return "未检测到星型结构"
        except Exception as e:
            return f"检测星型结构失败：{str(e)}"
    
    def get_filtered_sorted(self, filter_type, sort_type):
        try:
            result_ptr = self.dll.analyzer_get_filtered_sorted_new(self.analyzer, filter_type, sort_type)
            if result_ptr:
                return result_ptr.decode("utf-8")
            return "暂无数据"
        except Exception as e:
            return f"获取排序数据失败：{str(e)}"
    
    def get_violation_nodes(self):
        try:
            result_ptr = self.dll.analyzer_get_violation_nodes(self.analyzer)
            if result_ptr:
                return result_ptr.decode("utf-8")
            return "未检测到违规节点"
        except Exception as e:
            return f"检测违规节点失败：{str(e)}"
    
    def get_violation_sessions(self, src_ip, dst_start_ip, dst_end_ip):
        try:
            result_ptr = self.dll.analyzer_get_violation_sessions(
                self.analyzer, 
                src_ip.encode("utf-8"), 
                dst_start_ip.encode("utf-8"), 
                dst_end_ip.encode("utf-8")
            )
            if result_ptr:
                return result_ptr.decode("utf-8")
            return "未检测到违规会话"
        except Exception as e:
            return f"检测违规会话失败：{str(e)}"
    
    # 新增：获取邻接节点
    def get_neighbors(self, ip):
        try:
            buf_size = 2048
            first_order_buf = ctypes.create_string_buffer(buf_size)
            second_order_buf = ctypes.create_string_buffer(buf_size)
            
            ret = self.dll.get_neighbors(
                self.analyzer, ip.encode("utf-8"),
                first_order_buf, second_order_buf, buf_size
            )
            
            if ret == 0:
                return {"success": False, "msg": f"错误：节点 {ip} 不存在！"}
            elif ret == -1:
                return {"success": False, "msg": "分析器实例异常！"}
            
            # 解析结果
            first_order = first_order_buf.value.decode("utf-8").split(",") if first_order_buf.value else []
            second_order = second_order_buf.value.decode("utf-8").split(",") if second_order_buf.value else []
            
            # 去除空字符串
            first_order = [x for x in first_order if x.strip()]
            second_order = [x for x in second_order if x.strip()]
            
            return {
                "success": True,
                "first_order": first_order,
                "second_order": second_order,
                "ip": ip
            }
        except Exception as e:
            return {"success": False, "msg": f"获取邻接节点失败：{str(e)}"}
    
    # 新增：检测环结构
    def detect_cycles(self, filter_islands):
        try:
            result_ptr = self.dll.detect_cycles(self.analyzer, filter_islands)
            if result_ptr:
                return result_ptr.decode("utf-8")
            return "环检测失败"
        except Exception as e:
            return f"检测环结构失败：{str(e)}"

# 可视化工具类
class NetworkVisualizer:
    @staticmethod
    def draw_path_graph(parent_frame, shortest_path, least_congestion_path, start_ip, end_ip):
        """绘制路径可视化图"""
        # 清除原有画布
        for widget in parent_frame.winfo_children():
            widget.destroy()
        
        # 创建画布
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 6))
        fig.suptitle(f"路径可视化：{start_ip} → {end_ip}", fontsize=14, fontweight="bold")
        
        # 绘制跳数最小路径
        G1 = nx.DiGraph()
        G1.add_nodes_from(shortest_path)
        for i in range(len(shortest_path)-1):
            G1.add_edge(shortest_path[i], shortest_path[i+1])
        
        pos1 = nx.spring_layout(G1, seed=42)  # 固定布局种子
        nx.draw(G1, pos1, ax=ax1, with_labels=True, node_color="#4CAF50", 
                node_size=800, font_size=10, font_weight="bold", arrows=True)
        ax1.set_title(f"跳数最小路径（跳数：{len(shortest_path)-1}）", fontsize=12)
        
        # 绘制拥塞最小路径
        G2 = nx.DiGraph()
        G2.add_nodes_from(least_congestion_path)
        for i in range(len(least_congestion_path)-1):
            G2.add_edge(least_congestion_path[i], least_congestion_path[i+1])
        
        pos2 = nx.spring_layout(G2, seed=42)
        nx.draw(G2, pos2, ax=ax2, with_labels=True, node_color="#2196F3", 
                node_size=800, font_size=10, font_weight="bold", arrows=True)
        ax2.set_title(f"拥塞最小路径（跳数：{len(least_congestion_path)-1}）", fontsize=12)
        
        # 嵌入Tkinter
        canvas = FigureCanvasTkAgg(fig, master=parent_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        return canvas
    
    @staticmethod
    def draw_radial_star_graph(parent_frame, center_ip, neighbors, order_type="first"):
        """绘制放射状星图"""
        # 清除原有画布
        for widget in parent_frame.winfo_children():
            widget.destroy()
        
        if not neighbors:
            tk.Label(parent_frame, text=f"❌ {center_ip} 无{order_type}阶邻接节点", 
                     font=("微软雅黑", 12)).pack(pady=20)
            return None
        
        # 创建画布
        fig, ax = plt.subplots(figsize=(10, 10))
        fig.suptitle(f"{center_ip} 的{order_type}阶邻接节点放射状星图", fontsize=14, fontweight="bold")
        
        # 构建图
        G = nx.Graph()
        G.add_node(center_ip)
        G.add_nodes_from(neighbors)
        for neighbor in neighbors:
            G.add_edge(center_ip, neighbor)
        
        # 放射状布局
        pos = nx.circular_layout(G)
        # 调整中心节点位置
        pos[center_ip] = (0, 0)
        # 调整邻接节点位置为圆形
        import math
        n = len(neighbors)
        radius = 1.0
        for i, neighbor in enumerate(neighbors):
            angle = 2 * math.pi * i / n
            pos[neighbor] = (radius * math.cos(angle), radius * math.sin(angle))
        
        # 绘制
        nx.draw_networkx_nodes(G, pos, ax=ax, 
                               nodelist=[center_ip], node_color="#FF9800", node_size=1500, alpha=0.9)
        nx.draw_networkx_nodes(G, pos, ax=ax,
                               nodelist=neighbors, node_color="#9C27B0", node_size=800, alpha=0.8)
        nx.draw_networkx_edges(G, pos, ax=ax, width=2, alpha=0.7, edge_color="#607D8B")
        nx.draw_networkx_labels(G, pos, ax=ax, font_size=9, font_weight="bold")
        
        ax.set_xlim(-1.2, 1.2)
        ax.set_ylim(-1.2, 1.2)
        ax.axis("off")
        
        # 嵌入Tkinter
        canvas = FigureCanvasTkAgg(fig, master=parent_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        return canvas

# GUI界面
class NetworkAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("网络流量分析工具（可视化增强版）")
        self.root.geometry("1600x900")
        self.root.resizable(True, True)
        
        # 初始化DLL和可视化工具
        try:
            self.analyzer_dll = NetworkAnalyzerDLL()
            self.visualizer = NetworkVisualizer()
        except RuntimeError as e:
            messagebox.showerror("DLL加载失败", f"{str(e)}")
            sys.exit(1)
        
        self.current_csv_path = ""
        self.path_canvas = None
        self.star_canvas = None
        
        # 创建界面
        self._create_widgets()
    
    def _create_widgets(self):
        # 1. 顶部上传区域
        top_frame = tk.Frame(self.root, padx=10, pady=10, bg="#f0f0f0")
        top_frame.pack(fill=tk.X)
        
        self.upload_btn = tk.Button(top_frame, text="📁 上传CSV文件", command=self.upload_csv, 
                                   width=18, height=1, font=("微软雅黑", 10, "bold"), bg="#4CAF50", fg="white")
        self.upload_btn.pack(side=tk.LEFT, padx=5)
        
        self.file_label = tk.Label(top_frame, text="未加载文件", bg="#f0f0f0", font=("微软雅黑", 9))
        self.file_label.pack(side=tk.LEFT, padx=10, fill=tk.X, expand=True)
        
        # 2. 功能标签页
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # 2.1 路径分析（含可视化）
        path_frame = ttk.Frame(notebook)
        notebook.add(path_frame, text="路径分析（可视化）")
        self._create_path_tab(path_frame)
        
        # 2.2 放射状星图
        star_frame = ttk.Frame(notebook)
        notebook.add(star_frame, text="放射状星图（子图）")
        self._create_star_tab(star_frame)
        
        # 2.3 环结构检测
        cycle_frame = ttk.Frame(notebook)
        notebook.add(cycle_frame, text="环结构检测")
        self._create_cycle_tab(cycle_frame)
        
        # 保留原有标签页
        star_detect_frame = ttk.Frame(notebook)
        notebook.add(star_detect_frame, text="星型节点检测")
        self._create_star_detect_tab(star_detect_frame)
        
        sort_frame = ttk.Frame(notebook)
        notebook.add(sort_frame, text="排序与筛选")
        self._create_sort_tab(sort_frame)
        
        violation_node_frame = ttk.Frame(notebook)
        notebook.add(violation_node_frame, text="违规节点检测")
        self._create_violation_node_tab(violation_node_frame)
        
        violation_session_frame = ttk.Frame(notebook)
        notebook.add(violation_session_frame, text="违规会话检测")
        self._create_violation_session_tab(violation_session_frame)
        
        # 3. 结果显示区域（拆分：文本+可视化）
        result_main_frame = tk.Frame(self.root, padx=10, pady=10)
        result_main_frame.pack(fill=tk.BOTH, expand=True)
        
        # 3.1 文本结果区域
        text_frame = tk.Frame(result_main_frame, width=800)
        text_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        tk.Label(text_frame, text="📊 分析结果：", font=("微软雅黑", 11, "bold")).pack(side=tk.LEFT)
        self.result_title_label = tk.Label(text_frame, text="", font=("微软雅黑", 10), fg="#666")
        self.result_title_label.pack(side=tk.LEFT, padx=10)
        
        self.result_text = scrolledtext.ScrolledText(text_frame, wrap=tk.WORD, font=("Consolas", 10), 
                                                     bg="#f8f8f8", relief=tk.SUNKEN, bd=2)
        self.result_text.pack(fill=tk.BOTH, expand=True, pady=5)
        
        tk.Button(text_frame, text="清空结果", command=self.clear_result, 
                  width=10, bg="#f44336", fg="white").pack(side=tk.RIGHT, pady=5)
        
        # 3.2 可视化区域
        self.visual_frame = tk.Frame(result_main_frame, width=800, bd=2, relief=tk.GROOVE)
        self.visual_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        tk.Label(self.visual_frame, text="🎨 可视化区域", font=("微软雅黑", 11, "bold"), 
                 bg="#e0e0e0").pack(fill=tk.X)
    
    def _create_path_tab(self, parent):
        """路径分析（含可视化）"""
        frame = tk.Frame(parent, padx=20, pady=20)
        frame.pack(fill=tk.BOTH, expand=True)
        
        input_frame = tk.Frame(frame)
        input_frame.pack(fill=tk.X, pady=10)
        
        tk.Label(input_frame, text="源节点IP：", font=("微软雅黑", 10)).grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.start_ip_entry = tk.Entry(input_frame, font=("微软雅黑", 10), width=20)
        self.start_ip_entry.grid(row=0, column=1, padx=5, pady=5)
        
        tk.Label(input_frame, text="目的节点IP：", font=("微软雅黑", 10)).grid(row=0, column=2, padx=5, pady=5, sticky=tk.W)
        self.end_ip_entry = tk.Entry(input_frame, font=("微软雅黑", 10), width=20)
        self.end_ip_entry.grid(row=0, column=3, padx=5, pady=5)
        
        tk.Button(input_frame, text="🔍 查找路径（可视化）", command=self.find_paths_with_visual,
                  font=("微软雅黑", 10), bg="#2196F3", fg="white").grid(row=0, column=4, padx=10, pady=5)
        
        tk.Label(frame, text="路径说明：跳数=路径长度-1 | 拥塞程度=总流量/总时长（单位：bps）| 可视化无环",
                 font=("微软雅黑", 9), fg="#666").pack(anchor=tk.W, pady=5)
    
    def _create_star_tab(self, parent):
        """放射状星图（子图）"""
        frame = tk.Frame(parent, padx=20, pady=20)
        frame.pack(fill=tk.BOTH, expand=True)
        
        input_frame = tk.Frame(frame)
        input_frame.pack(fill=tk.X, pady=10)
        
        tk.Label(input_frame, text="中心节点IP：", font=("微软雅黑", 10)).grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.star_center_ip = tk.Entry(input_frame, font=("微软雅黑", 10), width=20)
        self.star_center_ip.grid(row=0, column=1, padx=5, pady=5)
        
        # 阶数选择
        self.star_order_var = tk.StringVar(value="first")
        tk.Radiobutton(input_frame, text="一阶邻接节点", variable=self.star_order_var, 
                       value="first", font=("微软雅黑", 9)).grid(row=0, column=2, padx=10)
        tk.Radiobutton(input_frame, text="二阶邻接节点", variable=self.star_order_var, 
                       value="second", font=("微软雅黑", 9)).grid(row=0, column=3, padx=10)
        
        tk.Button(input_frame, text="🎨 生成放射状星图", command=self.draw_star_graph,
                  font=("微软雅黑", 10), bg="#FF9800", fg="white").grid(row=0, column=4, padx=10, pady=5)
        
        tk.Label(frame, text="说明：一阶=直接相邻节点 | 二阶=相邻节点的相邻节点（排除自身）",
                 font=("微软雅黑", 9), fg="#666").pack(anchor=tk.W, pady=5)
    
    def _create_cycle_tab(self, parent):
        """环结构检测"""
        frame = tk.Frame(parent, padx=20, pady=20)
        frame.pack(fill=tk.BOTH, expand=True)
        
        # 筛选孤岛选项
        self.filter_islands_var = tk.BooleanVar(value=False)
        tk.Checkbutton(frame, text="仅显示孤岛节点对", variable=self.filter_islands_var,
                       font=("微软雅黑", 10)).pack(pady=10)
        
        tk.Button(frame, text="🔍 检测环结构", command=self.detect_cycles,
                  font=("微软雅黑", 10), bg="#e91e63", fg="white").pack(pady=10)
        
        tk.Label(frame, text="说明：\n① 3+节点环：包含3个及以上节点的回环路径\n② 互通节点：仅2个节点互环\n③ 孤岛：仅彼此相连的互通节点对",
                 font=("微软雅黑", 9), fg="#666", justify=tk.LEFT).pack(anchor=tk.W, pady=5)
    
    # 原有标签页实现（略作调整）
    def _create_star_detect_tab(self, parent):
        frame = tk.Frame(parent, padx=20, pady=20)
        frame.pack(fill=tk.BOTH, expand=True)
        
        tk.Button(frame, text="🚨 检测星型节点（简化规则）", command=self.show_star_structures_new,
                  font=("微软雅黑", 10), bg="#ff9800", fg="white").pack(pady=10)
        
        tk.Label(frame, text="星型节点规则：中心节点相邻节点数≥20",
                 font=("微软雅黑", 9), fg="#666").pack(anchor=tk.W, pady=5)
    
    def _create_sort_tab(self, parent):
        frame = tk.Frame(parent, padx=20, pady=20)
        frame.pack(fill=tk.BOTH, expand=True)
        
        filter_frame = tk.LabelFrame(frame, text="筛选方式", padx=10, pady=10, font=("微软雅黑", 10, "bold"))
        filter_frame.pack(fill=tk.X, pady=10)
        
        self.filter_var = tk.IntVar(value=0)
        tk.Radiobutton(filter_frame, text="无筛选", variable=self.filter_var, value=0, font=("微软雅黑", 9)).grid(row=0, column=0, padx=10)
        tk.Radiobutton(filter_frame, text="单向流量>80%节点（按data_size）", variable=self.filter_var, value=1, font=("微软雅黑", 9)).grid(row=0, column=1, padx=10)
        tk.Radiobutton(filter_frame, text="HTTPS节点", variable=self.filter_var, value=2, font=("微软雅黑", 9)).grid(row=0, column=2, padx=10)
        
        sort_frame = tk.LabelFrame(frame, text="排序方式", padx=10, pady=10, font=("微软雅黑", 10, "bold"))
        sort_frame.pack(fill=tk.X, pady=10)
        
        self.sort_var = tk.IntVar(value=0)
        tk.Radiobutton(sort_frame, text="按总会话数排序", variable=self.sort_var, value=0, font=("微软雅黑", 9)).grid(row=0, column=0, padx=10)
        tk.Radiobutton(sort_frame, text="按总时长排序", variable=self.sort_var, value=1, font=("微软雅黑", 9)).grid(row=0, column=1, padx=10)
        tk.Radiobutton(sort_frame, text="按总流量排序", variable=self.sort_var, value=2, font=("微软雅黑", 9)).grid(row=0, column=2, padx=10)
        
        tk.Button(frame, text="📊 执行排序筛选", command=self.execute_sort_filter,
                  font=("微软雅黑", 10), bg="#4CAF50", fg="white").pack(pady=10)
        
        tk.Label(frame, text="说明：所有筛选结果均会显示「源流量占总流量比例」列",
                 font=("微软雅黑", 9), fg="#666").pack(anchor=tk.W, pady=5)
    
    def _create_violation_node_tab(self, parent):
        frame = tk.Frame(parent, padx=20, pady=20)
        frame.pack(fill=tk.BOTH, expand=True)
        
        tk.Button(frame, text="🚨 检测违规节点", command=self.show_violation_nodes,
                  font=("微软雅黑", 10), bg="#e91e63", fg="white").pack(pady=10)
        
        tk.Label(frame, text="违规节点规则：源流量占比>90% 且 作为源的会话数>3",
                 font=("微软雅黑", 9), fg="#666").pack(anchor=tk.W, pady=5)
    
    def _create_violation_session_tab(self, parent):
        frame = tk.Frame(parent, padx=20, pady=20)
        frame.pack(fill=tk.BOTH, expand=True)
        
        input_frame = tk.Frame(frame)
        input_frame.pack(fill=tk.X, pady=10)
        
        tk.Label(input_frame, text="源IP：", font=("微软雅黑", 10)).grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.session_src_ip = tk.Entry(input_frame, font=("微软雅黑", 10), width=20)
        self.session_src_ip.grid(row=0, column=1, padx=5, pady=5)
        
        tk.Label(input_frame, text="目的IP起始：", font=("微软雅黑", 10)).grid(row=0, column=2, padx=5, pady=5, sticky=tk.W)
        self.session_dst_start = tk.Entry(input_frame, font=("微软雅黑", 10), width=20)
        self.session_dst_start.grid(row=0, column=3, padx=5, pady=5)
        
        tk.Label(input_frame, text="目的IP结束：", font=("微软雅黑", 10)).grid(row=0, column=4, padx=5, pady=5, sticky=tk.W)
        self.session_dst_end = tk.Entry(input_frame, font=("微软雅黑", 10), width=20)
        self.session_dst_end.grid(row=0, column=5, padx=5, pady=5)
        
        tk.Button(input_frame, text="🚨 检测违规会话", command=self.show_violation_sessions,
                  font=("微软雅黑", 10), bg="#9C27B0", fg="white").grid(row=0, column=6, padx=10, pady=5)
        
        tk.Label(frame, text="违规会话规则：指定源IP访问指定目的IP范围内的所有会话",
                 font=("微软雅黑", 9), fg="#666").pack(anchor=tk.W, pady=5)
    
    # 核心功能实现
    def upload_csv(self):
        try:
            file_path = filedialog.askopenfilename(
                title="选择CSV文件",
                filetypes=[("CSV文件", "*.csv"), ("所有文件", "*.*")]
            )
            if not file_path:
                return
            
            self.current_csv_path = file_path
            display_path = file_path if len(file_path) < 50 else "..." + file_path[-47:]
            self.file_label.config(text=f"当前文件：{display_path}")
            
            if self.analyzer_dll.read_csv(file_path):
                self.clear_result()
                self.result_text.insert(tk.END, f"✅ 成功加载文件：{file_path}\n\n请选择功能标签页进行分析\n")
        except Exception as e:
            messagebox.showerror("上传失败", f"错误：{str(e)}")
    
    def find_paths_with_visual(self):
        """路径查询+可视化"""
        if not self.current_csv_path:
            messagebox.showwarning("提示", "请先上传CSV文件！")
            return
        
        start_ip = self.start_ip_entry.get().strip()
        end_ip = self.end_ip_entry.get().strip()
        
        if not start_ip or not end_ip:
            messagebox.showwarning("提示", "请输入源节点和目的节点IP！")
            return
        
        # 调用DLL获取路径
        result = self.analyzer_dll.find_paths(start_ip, end_ip)
        self.result_title_label.config(text=f"路径分析：{start_ip} → {end_ip}")
        
        self.clear_result()
        if not result["success"]:
            self.result_text.insert(tk.END, result["msg"])
            return
        
        # 显示文本结果
        self.result_text.insert(tk.END, result["msg"])
        self.result_text.see(tk.INSERT)
        
        # 绘制路径可视化图
        self.path_canvas = self.visualizer.draw_path_graph(
            self.visual_frame,
            result["shortest_hop_path"],
            result["least_congestion_path"],
            start_ip,
            end_ip
        )
    
    def draw_star_graph(self):
        """生成放射状星图"""
        if not self.current_csv_path:
            messagebox.showwarning("提示", "请先上传CSV文件！")
            return
        
        center_ip = self.star_center_ip.get().strip()
        if not center_ip:
            messagebox.showwarning("提示", "请输入中心节点IP！")
            return
        
        # 获取邻接节点
        result = self.analyzer_dll.get_neighbors(center_ip)
        self.result_title_label.config(text=f"放射状星图：{center_ip}")
        
        self.clear_result()
        if not result["success"]:
            self.result_text.insert(tk.END, result["msg"])
            return
        
        # 选择阶数
        order_type = self.star_order_var.get()
        neighbors = result["first_order"] if order_type == "first" else result["second_order"]
        
        # 显示文本结果
        order_desc = "一阶" if order_type == "first" else "二阶"
        self.result_text.insert(tk.END, f"🌟 {center_ip} 的{order_desc}邻接节点：\n")
        self.result_text.insert(tk.END, f"总计：{len(neighbors)} 个\n")
        self.result_text.insert(tk.END, "节点列表：\n" + "\n".join(neighbors))
        
        # 绘制放射状星图
        self.star_canvas = self.visualizer.draw_radial_star_graph(
            self.visual_frame,
            center_ip,
            neighbors,
            order_desc
        )
    
    def detect_cycles(self):
        """检测环结构"""
        if not self.current_csv_path:
            messagebox.showwarning("提示", "请先上传CSV文件！")
            return
        
        filter_islands = self.filter_islands_var.get()
        self.result_title_label.config(text="环结构检测结果")
        
        # 调用DLL检测环
        result = self.analyzer_dll.detect_cycles(filter_islands)
        
        self.clear_result()
        self.result_text.insert(tk.END, result)
        self.result_text.see(tk.INSERT)
        
        # 清空可视化区域
        for widget in self.visual_frame.winfo_children():
            widget.destroy()
        tk.Label(self.visual_frame, text="环结构检测结果仅文本展示", 
                 font=("微软雅黑", 12)).pack(pady=20)
    
    # 原有功能实现
    def show_star_structures_new(self):
        if not self.current_csv_path:
            messagebox.showwarning("提示", "请先上传CSV文件！")
            return
        
        self.result_title_label.config(text="星型节点检测（简化规则）")
        result = self.analyzer_dll.get_star_structures_new()
        
        self.clear_result()
        self.result_text.insert(tk.END, result)
        self.result_text.see(tk.INSERT)
        
        # 清空可视化区域
        for widget in self.visual_frame.winfo_children():
            widget.destroy()
        tk.Label(self.visual_frame, text="星型节点检测结果仅文本展示", 
                 font=("微软雅黑", 12)).pack(pady=20)
    
    def execute_sort_filter(self):
        if not self.current_csv_path:
            messagebox.showwarning("提示", "请先上传CSV文件！")
            return
        
        filter_type = self.filter_var.get()
        sort_type = self.sort_var.get()
        
        filter_names = ["无筛选", "单向流量>80%（按data_size）", "HTTPS节点"]
        sort_names = ["总会话数", "总时长", "总流量"]
        
        self.result_title_label.config(text=f"排序筛选：{filter_names[filter_type]} + 按{sort_names[sort_type]}排序")
        result = self.analyzer_dll.get_filtered_sorted(filter_type, sort_type)
        
        self.clear_result()
        self.result_text.insert(tk.END, result)
        self.result_text.see(tk.INSERT)
        
        # 清空可视化区域
        for widget in self.visual_frame.winfo_children():
            widget.destroy()
        tk.Label(self.visual_frame, text="排序筛选结果仅文本展示", 
                 font=("微软雅黑", 12)).pack(pady=20)
    
    def show_violation_nodes(self):
        if not self.current_csv_path:
            messagebox.showwarning("提示", "请先上传CSV文件！")
            return
        
        self.result_title_label.config(text="违规节点检测结果")
        result = self.analyzer_dll.get_violation_nodes()
        
        self.clear_result()
        self.result_text.insert(tk.END, result)
        self.result_text.see(tk.INSERT)
        
        # 清空可视化区域
        for widget in self.visual_frame.winfo_children():
            widget.destroy()
        tk.Label(self.visual_frame, text="违规节点检测结果仅文本展示", 
                 font=("微软雅黑", 12)).pack(pady=20)
    
    def show_violation_sessions(self):
        if not self.current_csv_path:
            messagebox.showwarning("提示", "请先上传CSV文件！")
            return
        
        src_ip = self.session_src_ip.get().strip()
        dst_start = self.session_dst_start.get().strip()
        dst_end = self.session_dst_end.get().strip()
        
        if not src_ip or not dst_start or not dst_end:
            messagebox.showwarning("提示", "请完整输入源IP和目的IP范围！")
            return
        
        self.result_title_label.config(text=f"违规会话检测：源IP={src_ip} 目的IP范围=[{dst_start}, {dst_end}]")
        result = self.analyzer_dll.get_violation_sessions(src_ip, dst_start, dst_end)
        
        self.clear_result()
        self.result_text.insert(tk.END, result)
        self.result_text.see(tk.INSERT)
        
        # 清空可视化区域
        for widget in self.visual_frame.winfo_children():
            widget.destroy()
        tk.Label(self.visual_frame, text="违规会话检测结果仅文本展示", 
                 font=("微软雅黑", 12)).pack(pady=20)
    
    def clear_result(self):
        """清空结果"""
        self.result_text.delete(1.0, tk.END)
        # 清空可视化画布
        if self.path_canvas:
            self.path_canvas.get_tk_widget().destroy()
            self.path_canvas = None
        if self.star_canvas:
            self.star_canvas.get_tk_widget().destroy()
            self.star_canvas = None
        # 清空可视化区域
        for widget in self.visual_frame.winfo_children()[1:]:  # 保留标题
            widget.destroy()

# 主函数
if __name__ == "__main__":
    try:
        root = tk.Tk()
        app = NetworkAnalyzerGUI(root)
        
        def on_closing():
            del app.analyzer_dll
            root.destroy()
        root.protocol("WM_DELETE_WINDOW", on_closing)
        
        root.mainloop()
    except Exception as e:
        messagebox.showerror("程序崩溃", f"启动失败：{str(e)}")
        sys.exit(1)