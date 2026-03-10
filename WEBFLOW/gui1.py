import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
import ctypes
import os
import sys

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
            # 创建实例
            self.dll.create_analyzer.restype = ctypes.c_void_p
            self.dll.create_analyzer.argtypes = []
            
            # 读取CSV
            self.dll.analyzer_read_csv.restype = ctypes.c_bool
            self.dll.analyzer_read_csv.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
            
            # 寻路算法：跳数最小
            self.dll.find_shortest_hop_path.restype = ctypes.c_int
            self.dll.find_shortest_hop_path.argtypes = [
                ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p,
                ctypes.c_char_p, ctypes.POINTER(ctypes.c_double), ctypes.c_int
            ]
            
            # 寻路算法：拥塞最小
            self.dll.find_least_congestion_path.restype = ctypes.c_int
            self.dll.find_least_congestion_path.argtypes = [
                ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p,
                ctypes.c_char_p, ctypes.POINTER(ctypes.c_double), ctypes.c_int
            ]
            
            # 星型节点（简化规则）
            self.dll.analyzer_get_star_structures_new.restype = ctypes.c_char_p
            self.dll.analyzer_get_star_structures_new.argtypes = [ctypes.c_void_p]
            
            # 流量排序
            self.dll.analyzer_sort_by_data.restype = ctypes.c_char_p
            self.dll.analyzer_sort_by_data.argtypes = [ctypes.c_void_p]
            
            # 筛选+排序（新）
            self.dll.analyzer_get_filtered_sorted_new.restype = ctypes.c_char_p
            self.dll.analyzer_get_filtered_sorted_new.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int]
            
            # 违规节点检测
            self.dll.analyzer_get_violation_nodes.restype = ctypes.c_char_p
            self.dll.analyzer_get_violation_nodes.argtypes = [ctypes.c_void_p]
            
            # 新增：违规会话检测
            self.dll.analyzer_get_violation_sessions.restype = ctypes.c_char_p
            self.dll.analyzer_get_violation_sessions.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
            
            # 检查节点是否存在
            self.dll.analyzer_is_node_exist.restype = ctypes.c_bool
            self.dll.analyzer_is_node_exist.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
            
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
        """获取跳数最小和拥塞最小路径"""
        try:
            if not self.dll.analyzer_is_node_exist(self.analyzer, start_ip.encode("utf-8")):
                return f"错误：源节点 {start_ip} 不存在！"
            if not self.dll.analyzer_is_node_exist(self.analyzer, end_ip.encode("utf-8")):
                return f"错误：目的节点 {end_ip} 不存在！"
            
            buf_size = 1024
            path_buf = ctypes.create_string_buffer(buf_size)
            avg_congestion = ctypes.c_double(0.0)
            
            hop_count = self.dll.find_shortest_hop_path(
                self.analyzer, start_ip.encode("utf-8"), end_ip.encode("utf-8"),
                path_buf, ctypes.byref(avg_congestion), buf_size
            )
            if hop_count == -2:
                return f"错误：{start_ip} 和 {end_ip} 之间无连通路径！"
            shortest_hop_path = path_buf.value.decode("utf-8")
            shortest_hop_congestion = avg_congestion.value
            
            congestion_hop_count = self.dll.find_least_congestion_path(
                self.analyzer, start_ip.encode("utf-8"), end_ip.encode("utf-8"),
                path_buf, ctypes.byref(avg_congestion), buf_size
            )
            least_congestion_path = path_buf.value.decode("utf-8")
            least_congestion_value = avg_congestion.value
            
            result = f"📌 跳数最小路径：\n{shortest_hop_path}\n"
            result += f"跳数：{hop_count} | 平均拥塞程度：{shortest_hop_congestion:.2f} bps\n\n"
            result += f"📌 拥塞程度最小路径：\n{least_congestion_path}\n"
            result += f"跳数：{congestion_hop_count} | 平均拥塞程度：{least_congestion_value:.2f} bps"
            return result
        except Exception as e:
            return f"寻路失败：{str(e)}"
    
    def get_star_structures_new(self):
        """星型节点（简化规则）"""
        try:
            result_ptr = self.dll.analyzer_get_star_structures_new(self.analyzer)
            if result_ptr:
                return result_ptr.decode("utf-8")
            return "未检测到星型结构"
        except Exception as e:
            return f"检测星型结构失败：{str(e)}"
    
    def get_filtered_sorted(self, filter_type, sort_type):
        """筛选+排序（新逻辑）"""
        try:
            result_ptr = self.dll.analyzer_get_filtered_sorted_new(self.analyzer, filter_type, sort_type)
            if result_ptr:
                return result_ptr.decode("utf-8")
            return "暂无数据"
        except Exception as e:
            return f"获取排序数据失败：{str(e)}"
    
    def get_violation_nodes(self):
        """违规节点检测"""
        try:
            result_ptr = self.dll.analyzer_get_violation_nodes(self.analyzer)
            if result_ptr:
                return result_ptr.decode("utf-8")
            return "未检测到违规节点"
        except Exception as e:
            return f"检测违规节点失败：{str(e)}"
    
    # 新增：违规会话检测
    def get_violation_sessions(self, src_ip, dst_start_ip, dst_end_ip):
        """违规会话检测"""
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

# GUI界面
class NetworkAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("网络流量分析工具（增强版）")
        self.root.geometry("1500x850")
        self.root.resizable(True, True)
        
        # 初始化DLL
        try:
            self.analyzer_dll = NetworkAnalyzerDLL()
        except RuntimeError as e:
            messagebox.showerror("DLL加载失败", f"{str(e)}")
            sys.exit(1)
        
        self.current_csv_path = ""
        
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
        
        # 2.1 寻路功能标签页
        path_frame = ttk.Frame(notebook)
        notebook.add(path_frame, text="路径分析")
        self._create_path_tab(path_frame)
        
        # 2.2 星型节点标签页
        star_frame = ttk.Frame(notebook)
        notebook.add(star_frame, text="星型节点检测")
        self._create_star_tab(star_frame)
        
        # 2.3 排序筛选标签页
        sort_frame = ttk.Frame(notebook)
        notebook.add(sort_frame, text="排序与筛选")
        self._create_sort_tab(sort_frame)
        
        # 2.4 违规节点检测标签页
        violation_frame = ttk.Frame(notebook)
        notebook.add(violation_frame, text="违规节点检测")
        self._create_violation_tab(violation_frame)
        
        # 2.5 新增：违规会话检测标签页
        session_frame = ttk.Frame(notebook)
        notebook.add(session_frame, text="违规会话检测")
        self._create_session_tab(session_frame)
        
        # 3. 结果显示区域
        result_frame = tk.Frame(self.root, padx=10, pady=10)
        result_frame.pack(fill=tk.BOTH, expand=True)
        
        tk.Label(result_frame, text="📊 分析结果：", font=("微软雅黑", 11, "bold")).pack(side=tk.LEFT)
        self.result_title_label = tk.Label(result_frame, text="", font=("微软雅黑", 10), fg="#666")
        self.result_title_label.pack(side=tk.LEFT, padx=10)
        
        self.result_text = scrolledtext.ScrolledText(result_frame, wrap=tk.WORD, font=("Consolas", 11), 
                                                     bg="#f8f8f8", relief=tk.SUNKEN, bd=2)
        self.result_text.pack(fill=tk.BOTH, expand=True, pady=5)
        
        tk.Button(result_frame, text="清空结果", command=self.clear_result, 
                  width=10, bg="#f44336", fg="white").pack(side=tk.RIGHT, pady=5)
    
    def _create_path_tab(self, parent):
        """寻路功能界面"""
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
        
        tk.Button(input_frame, text="🔍 查找路径", command=self.find_paths, 
                  font=("微软雅黑", 10), bg="#2196F3", fg="white").grid(row=0, column=4, padx=10, pady=5)
        
        tk.Label(frame, text="路径说明：跳数=路径长度-1 | 拥塞程度=总流量/总时长（单位：bps）", 
                 font=("微软雅黑", 9), fg="#666").pack(anchor=tk.W, pady=5)
    
    def _create_star_tab(self, parent):
        """星型节点检测界面（简化规则）"""
        frame = tk.Frame(parent, padx=20, pady=20)
        frame.pack(fill=tk.BOTH, expand=True)
        
        tk.Button(frame, text="🚨 检测星型节点", command=self.show_star_structures_new,
                  font=("微软雅黑", 10), bg="#ff9800", fg="white").pack(pady=10)
        
        tk.Label(frame, text="星型节点规则：中心节点相邻节点数≥20且边界节点数大于10",
                 font=("微软雅黑", 9), fg="#666").pack(anchor=tk.W, pady=5)
    
    def _create_sort_tab(self, parent):
        """排序筛选界面（嵌套逻辑）"""
        frame = tk.Frame(parent, padx=20, pady=20)
        frame.pack(fill=tk.BOTH, expand=True)
        
        # 筛选选择
        filter_frame = tk.LabelFrame(frame, text="筛选方式", padx=10, pady=10, font=("微软雅黑", 10, "bold"))
        filter_frame.pack(fill=tk.X, pady=10)
        
        self.filter_var = tk.IntVar(value=0)
        tk.Radiobutton(filter_frame, text="无筛选", variable=self.filter_var, value=0, font=("微软雅黑", 9)).grid(row=0, column=0, padx=10)
        tk.Radiobutton(filter_frame, text="单向流量>80%节点（按data_size）", variable=self.filter_var, value=1, font=("微软雅黑", 9)).grid(row=0, column=1, padx=10)
        tk.Radiobutton(filter_frame, text="HTTPS节点", variable=self.filter_var, value=2, font=("微软雅黑", 9)).grid(row=0, column=2, padx=10)
        
        # 排序选择
        sort_frame = tk.LabelFrame(frame, text="排序方式", padx=10, pady=10, font=("微软雅黑", 10, "bold"))
        sort_frame.pack(fill=tk.X, pady=10)
        
        self.sort_var = tk.IntVar(value=0)
        tk.Radiobutton(sort_frame, text="按总会话数排序", variable=self.sort_var, value=0, font=("微软雅黑", 9)).grid(row=0, column=0, padx=10)
        tk.Radiobutton(sort_frame, text="按总时长排序", variable=self.sort_var, value=1, font=("微软雅黑", 9)).grid(row=0, column=1, padx=10)
        tk.Radiobutton(sort_frame, text="按总流量排序", variable=self.sort_var, value=2, font=("微软雅黑", 9)).grid(row=0, column=2, padx=10)
        
        # 执行按钮
        tk.Button(frame, text="📊 执行排序筛选", command=self.execute_sort_filter,
                  font=("微软雅黑", 10), bg="#4CAF50", fg="white").pack(pady=10)
        
        # 说明文字
        tk.Label(frame, text="说明：所有筛选结果均会显示「源流量占总流量比例」列",
                 font=("微软雅黑", 9), fg="#666").pack(anchor=tk.W, pady=5)
    
    def _create_violation_tab(self, parent):
        """违规节点检测界面"""
        frame = tk.Frame(parent, padx=20, pady=20)
        frame.pack(fill=tk.BOTH, expand=True)
        
        tk.Button(frame, text="🚨 检测违规节点", command=self.show_violation_nodes,
                  font=("微软雅黑", 10), bg="#e91e63", fg="white").pack(pady=10)
        
        tk.Label(frame, text="违规节点规则：源流量占比>90% 且 作为源的会话数>3",
                 font=("微软雅黑", 9), fg="#666").pack(anchor=tk.W, pady=5)
    
    # 新增：违规会话检测界面
    def _create_session_tab(self, parent):
        """违规会话检测界面"""
        frame = tk.Frame(parent, padx=20, pady=20)
        frame.pack(fill=tk.BOTH, expand=True)
        
        input_frame = tk.Frame(frame)
        input_frame.pack(fill=tk.X, pady=10)
        
        # 源IP输入
        tk.Label(input_frame, text="源IP：", font=("微软雅黑", 10)).grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.session_src_ip = tk.Entry(input_frame, font=("微软雅黑", 10), width=20)
        self.session_src_ip.grid(row=0, column=1, padx=5, pady=5)
        
        # 目的IP起始范围
        tk.Label(input_frame, text="目的IP起始：", font=("微软雅黑", 10)).grid(row=0, column=2, padx=5, pady=5, sticky=tk.W)
        self.session_dst_start = tk.Entry(input_frame, font=("微软雅黑", 10), width=20)
        self.session_dst_start.grid(row=0, column=3, padx=5, pady=5)
        
        # 目的IP结束范围
        tk.Label(input_frame, text="目的IP结束：", font=("微软雅黑", 10)).grid(row=0, column=4, padx=5, pady=5, sticky=tk.W)
        self.session_dst_end = tk.Entry(input_frame, font=("微软雅黑", 10), width=20)
        self.session_dst_end.grid(row=0, column=5, padx=5, pady=5)
        
        # 检测按钮
        tk.Button(input_frame, text="🚨 检测违规会话", command=self.show_violation_sessions,
                  font=("微软雅黑", 10), bg="#9C27B0", fg="white").grid(row=0, column=6, padx=10, pady=5)
        
        # 说明文字
        tk.Label(frame, text="违规会话规则：指定源IP访问指定目的IP范围内的所有会话",
                 font=("微软雅黑", 9), fg="#666").pack(anchor=tk.W, pady=5)
    
    def upload_csv(self):
        """上传CSV"""
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
    
    def find_paths(self):
        """寻路功能"""
        if not self.current_csv_path:
            messagebox.showwarning("提示", "请先上传CSV文件！")
            return
        
        start_ip = self.start_ip_entry.get().strip()
        end_ip = self.end_ip_entry.get().strip()
        
        if not start_ip or not end_ip:
            messagebox.showwarning("提示", "请输入源节点和目的节点IP！")
            return
        
        self.result_title_label.config(text=f"路径分析：{start_ip} → {end_ip}")
        result = self.analyzer_dll.find_paths(start_ip, end_ip)
        
        self.clear_result()
        self.result_text.insert(tk.END, result)
        self.result_text.see(tk.INSERT)
    
    def show_star_structures_new(self):
        """星型节点检测"""
        if not self.current_csv_path:
            messagebox.showwarning("提示", "请先上传CSV文件！")
            return
        
        self.result_title_label.config(text="星型节点检测")
        result = self.analyzer_dll.get_star_structures_new()
        
        self.clear_result()
        self.result_text.insert(tk.END, result)
        self.result_text.see(tk.INSERT)
    
    def execute_sort_filter(self):
        """执行排序筛选"""
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
    
    def show_violation_nodes(self):
        """违规节点检测"""
        if not self.current_csv_path:
            messagebox.showwarning("提示", "请先上传CSV文件！")
            return
        
        self.result_title_label.config(text="违规节点检测结果")
        result = self.analyzer_dll.get_violation_nodes()
        
        self.clear_result()
        self.result_text.insert(tk.END, result)
        self.result_text.see(tk.INSERT)
    
    # 新增：违规会话检测
    def show_violation_sessions(self):
        """违规会话检测"""
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
    
    def clear_result(self):
        """清空结果"""
        self.result_text.delete(1.0, tk.END)

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