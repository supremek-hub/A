import time
from numpy import roots
from scapy.all import ARP,Ether,srp
import socket
import os
import tkinter as tk
from tkinter import ttk, END
from tkinter import scrolledtext
from tkinter.scrolledtext import ScrolledText
from manuf import manuf 
import json
import psutil
import threading
import concurrent.futures
import nmap
import ipaddress
import threading
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from datetime import datetime
from mac_vendor_lookup import MacLookup
from rich import print as rprint 
from jinja2 import Environment, FileSystemLoader
vendor_lookup = MacLookup()
parser = manuf.MacParser()
COMMON_SERVICES = { 20: "FTP Data", 21: "FTP Control", 22: "SSH", 23: "Telnet",25: "SMTP",53: "DNS",67: "DHCP Server",68: "DHCP Client",80: "HTTP",110: "POP3",143: "IMAP",443: "HTTPS",3306: "MySQL Database",3389: "Remote Desktop",5900: "VNC",8080: "HTTP Proxy"}
CONFIG_FILE ="config.json"
def run_scan_threaded(self):
    scan_thread = threading.Thread(target=self.run_scan, daemon=True)
    scan_thread.start()
def export_html_report(devices, filename="scan_results/report.html"):
    os.makedirs("scan_results", exist_ok=True)
    env = Environment(loader=FileSystemLoader("templates"))
    template = env.get_template("report_template.html")
    output = template.render(devices=devices, timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    with open(filename, "w") as f:
        f.write(output)
def export_pdf_report(devices, filename="scan_results/report.pdf"):
    os.makedirs("scan_results", exist_ok=True)
    c = canvas.Canvas(filename, pagesize=letter)
    width, height = letter
    c.setFont("Helvetica-Bold", 16)
    c.drawString(100, height - 50, "Network Scan Report")
    c.setFont("Helvetica", 12)
    c.drawString(100, height - 70, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    y = height - 100
    for device in devices:
        if y < 100:
            c.showPage()
            y = height - 100
        c.drawString(50, y, f"IP: {device['IP']} | Hostname: {device['Hostname']}")
        y -= 15
        c.drawString(50, y, f"MAC: {device['MAC']} | Vendor: {device.get('Vendor', 'N/A')} | OS: {device.get('OS', 'N/A')}")
        y -= 15
        c.drawString(50, y, f"Open Ports:")
        y -= 15
        ports = device.get("Ports", {})
        if ports:
            for port, service in ports.items():
                c.drawString(70, y, f"- Port {port}: {service}")
                y -= 15
                if y < 100:
                    c.showPage()
                    y = height - 100
        else:
            c.drawString(70, y, "None")
            y -= 15
        c.drawString(50, y, "-" * 80)
        y -= 20
    c.save()
def load_config():
    if not os.path.exists(CONFIG_FILE):
        raise FileNotFoundError("config.json not found. Please create it.")
    with open(CONFIG_FILE, 'r') as file:
        return json.load(file)
config = load_config()
def get_mac_vendor(mac):
    return parser.get_manuf(mac)
def detect_os(ip):
    try:
        nm = nmap.PortScanner()
        nm.scan(ip, arguments="-O")  
        if 'osmatch' in nm[ip]:
            os_match = nm[ip]['osmatch']
            if os_match:
                return os_match[0]['name']
        return "Unknown OS"
    except Exception as e:
        return "Unknown OS"
def get_all_network_ranges():
    networks = []
    for interface, addresses in psutil.net_if_addrs().items():
        for addr in addresses:
            if addr.family == 2:
                ip = addr.address
                try:
                    network = str(ipaddress.IPv4Network(ip + "/24",strict=False))
                    networks.append(network)
                except:
                    continue
    return networks
def scan_network(ip_range):
    print(f"Scanning: {ip_range} ...")
    arp_request = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether /arp_request
    try:
        result = srp(packet, timeout=3, verbose=False)[0]
    except Exception as e:
        print(f"Error scanning {ip_range}: {e}")
        return []
    device = []
    for sent,received in result:
        hostname = get_device_hostname(received.psrc)
        os_guess = detect_os(received.psrc)
        try:
            vendor = get_mac_vendor(received.hwsrc)
        except:
            vendor = "Unknown Vendor"
        device.append({"IP": received.psrc,"MAC": received.hwsrc,"Hostname": hostname,"Vendor": vendor, "OS": os_guess})
    return device
def get_device_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown"
def scan_ports(ip, port_range=None, thread_limit=None):
    if port_range is None:
        # Limit to common ports for faster scans if no custom config
        port_range = tuple(config.get("port_range", [20, 1024]))
    if thread_limit is None:
        thread_limit = config.get("thread_limit", 200)
    open_ports = {}
    lock = threading.Lock()
    def scan_port(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(config.get("timeout", 0.2))  # Slightly higher for accuracy
                if sock.connect_ex((ip, port)) == 0:
                    try:
                        service = socket.getservbyport(port)
                    except:
                        service = COMMON_SERVICES.get(port, "Unknown Service")
                    with lock:
                        open_ports[port] = service
        except:
            pass  # Fail quietly, continue scanning
    with concurrent.futures.ThreadPoolExecutor(max_workers=thread_limit) as executor:
        executor.map(scan_port, range(port_range[0], port_range[1] + 1))
    return open_ports
def save_results(devices):
    os.makedirs("scan_results", exist_ok=True)
    '''with open("scan_results/scan_results.json",'w') as json_file:
        json.dump(devices,json_file, indent=4)
    with open("scan_results/scan_results.txt", "w") as txt_file:
        for device in devices:
            txt_file.write(f"\nDevice: {device['IP']}({device['Hostname']})\n")
            txt_file.write(f"MAC Address: {device['MAC']}\n")
            ports = device.get("Ports", {})
            if not ports:
                txt_file.write("  No open ports detected.\n")
            else:
                txt_file.write("Open Ports:\n")
                for port,service in device["Ports"].items():
                    txt_file.write(f"  Port  {port}: {service}\n")
            txt_file.write("-" * 30 + "\n")'''
    export_pdf_report(devices)
    export_html_report(devices)
def compare_devices(old, new):
    old_ips = {dev['IP']: dev for dev in old}
    new_ips = {dev['IP']: dev for dev in new}
    added = [dev for ip, dev in new_ips.items() if ip not in old_ips]
    removed = [dev for ip, dev in old_ips.items() if ip not in new_ips]
    changed_ports = []
    for ip in new_ips:
        if ip in old_ips:
            old_ports = old_ips[ip].get("ports", {})
            new_ports = new_ips[ip].get("ports", {})
            if old_ports != new_ports:
                changed_ports.append({"IP": ip, "Old": old_ports, "New": new_ports})
    return added, removed, changed_ports
def run_full_scan(self, output_box=None):
    def log(msg):
        if output_box:
            output_box.insert(tk.END, msg + "\n")
            output_box.see(tk.END)
            output_box.update()
        else:
            print(msg)
    devices = []
    networks = get_all_network_ranges()
    total_networks = len(networks) 
    if not networks:
        log("⚠️ No active networks found.")
        return devices 
    log(f"🌐 Detected Networks: {networks}\n")
    self.progress["maximum"] = total_networks
    self.progress["value"] = 0
    for i, network in enumerate(networks, start=1):
        log(f"🔍 Scanning network: {network}")
        scanned_devices = scan_network(network)
        devices.extend(scanned_devices)
        self.progress["value"] = i
        self.progress.update()
        time.sleep(0.2)  # Simulate progress visually
    if not devices:
        log("⚠️ No devices found.")
        return devices
    log(f"\n🖥️ Devices Found: {len(devices)}\n")
    self.progress["maximum"] = len(devices)
    self.progress["value"] = 0
    for i, device in enumerate(devices, start=1):
        log(f"📡 {device['IP']} ({device['Hostname']}) - Scanning ports...")
        open_ports = scan_ports(device['IP'])
        device["Ports"] = open_ports
        device['OS'] = detect_os(device['IP'])
        if open_ports:
            log(f"✅ Open Ports for {device['IP']}:")
            for port, service in open_ports.items():
                log(f"  Port {port}: {service}")
        else:
            log(f"❌ No open ports found for {device['IP']}.")
        log("")  # Blank line after each device
        self.progress["value"] = i
        self.progress.update()
        time.sleep(0.1)
    self.progress["value"] = 0  # Reset progress
    log("✅ Scan Complete.\n")
    return devices
def auto_scan_loop():
    previous_scan = []
    while config.get("enable_auto_scan", False):
        print("\n[Auto Scan Triggered]")
        current_scan = run_full_scan()
        added, removed, changed = compare_devices(previous_scan, current_scan)
        if added:
            print(f"[+] New Devices Detected:")
            for d in added:
                print(f"  {d['IP']} ({d.get('Hostname')}) - {d.get('Vendor')}")
        if removed:
            print(f"[-] Devices Disconnected:")
            for d in removed:
                print(f"  {d['IP']} ({d.get('Hostname')})")
        if changed:
            print(f"[!] Port Changes Detected:")
            for change in changed:
                print(f"  {change['IP']}: Ports changed.")
        save_results(current_scan)
        previous_scan = current_scan
        time.sleep(config.get("auto_scan_interval_seconds", 300))
'''networks = get_all_network_ranges()
if not networks:
    print("No active networks found. Exiting...")
    exit()
print(f"Detected Networks: {networks}")
all_devices = []
for network in networks:
    devices = scan_network(network)
    all_devices.extend(devices)
if all_devices:
    print("\nConnected Devices:")
    print("IP Address\t\tMac Address\t\tHostname\t\tVendor\t\tOS")
    for device in all_devices:
        print(f"{device['IP']}\t{device['MAC']}\t{device['Hostname']}\t\t{device['Vendor']}\t{device['OS']}")
    for device in all_devices:
        print(f"\nScanning ports for {device['IP']}({device['Hostname']}) ...")
        open_ports = scan_ports(device['IP'])
        device["Ports"] = open_ports
        device["OS"] = detect_os(device["IP"])
        if open_ports:
            print("Open Ports and Services:")
            for port, service in open_ports.items():
                print(f"Port {port}: {service}")
        else:
            print("No open ports detected.")
    if "json" in config.get("output_format", []):
        save_results(all_devices)
    print("\nResults saved in 'scan_results/' folder.")
    print("📁 Reports generated: scan_results/report.pdf & report.html")
else: print("\nNo device detected. Try running as Administrator or check network settings.")'''
class CyberScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Cybersecurity Scanner")
        self.root.geometry("1000x600")
        self.tab_control = ttk.Notebook(self.root)
        self.tab1 = ttk.Frame(self.tab_control)
        self.tab2 = ttk.Frame(self.tab_control)
        self.tab3 = ttk.Frame(self.tab_control)
        self.tab_control.add(self.tab1, text='Devices')
        self.tab_control.add(self.tab2, text='Open Ports')
        self.tab_control.add(self.tab3, text='Summary')
        self.tab_control.pack(expand=1, fill='both')
        self.output_box = scrolledtext.ScrolledText(self.tab3, wrap=tk.WORD, width=120, height=30)
        self.output_box.pack(padx=10, pady=10)
        self.device_tree = ttk.Treeview(self.tab1, columns=("IP", "MAC", "Hostname", "Vendor", "OS"), show='headings')
        for col in ("IP", "MAC", "Hostname", "Vendor", "OS"):
            self.device_tree.heading(col, text=col)
        self.device_tree.pack(fill='both', expand=True)
        self.port_tree = ttk.Treeview(self.tab2, columns=("IP", "Port", "Service"), show='headings')
        for col in ("IP", "Port", "Service"):
            self.port_tree.heading(col, text=col)
        self.port_tree.pack(fill='both', expand=True)
        self.scan_button = ttk.Button(self.tab1, text="Start Scan", command=self.run_scan_thread)
        self.scan_button.pack(pady=10)
        self.progress = ttk.Progressbar(self.tab3, orient="horizontal", mode="determinate", length=800)
        self.progress.pack(pady=5)
        self.last_scan_results = []
    def run_scan_thread(self):
        threading.Thread(target=self.run_scan_and_display).start()
    def run_scan_and_display(self):
        self.output_box.delete("1.0", tk.END)  # Clear previous output
        devices = run_full_scan(self, output_box=self.output_box)
        if not devices:
            self.output_box.insert(tk.END, "No devices found.\n")
            return
        for item in self.device_tree.get_children():
            self.device_tree.delete(item)
        for item in self.port_tree.get_children():
            self.port_tree.delete(item)
        for device in devices:
            self.device_tree.insert("", "end", values=(
                device.get("IP", "N/A"),
                device.get("MAC", "N/A"),
                device.get("Hostname", "Unknown"),
                device.get("Vendor", "Unknown"),
                device.get("OS", "Unknown OS")
            ))
            ip = device.get("IP", "N/A")
            ports = device.get("Ports", {})
            for port, service in ports.items():
                self.port_tree.insert("", "end", values=(ip, port, service))
        self.last_scan_results = devices
if __name__ == '__main__':
    root = tk.Tk()
    app = CyberScannerApp(root)
    root.mainloop()
