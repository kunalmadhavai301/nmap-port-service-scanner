from flask import Flask, request, jsonify, render_template, send_file
import nmap
import pandas as pd
import os
from datetime import datetime

# ---------------- OOP Classes ----------------
class Port:
    def __init__(self, port_num, status):
        self.port_num = port_num
        self.status = status

class Service:
    def __init__(self, name, version):
        self.name = name
        self.version = version

class TargetHost:
    def __init__(self, ip, hostname=None):
        self.ip = ip
        self.hostname = hostname
        self.ports = []
        self.os = None

    def add_port(self, port):
        self.ports.append(port)

    def set_os(self, os_name):
        self.os = os_name

class NmapScanner:
    def __init__(self):
        self.scanner = nmap.PortScanner()
        self.results = []

    def run_scan(self, target_ip, scan_type="fast"):
        scan_args = "-T4 -F" if scan_type == "fast" else "-A -T4"
        self.scanner.scan(hosts=target_ip, arguments=scan_args)

        for host in self.scanner.all_hosts():
            target = TargetHost(host, self.scanner[host].hostname())

            # OS Detection
            if "osmatch" in self.scanner[host]:
                if self.scanner[host]["osmatch"]:
                    target.set_os(self.scanner[host]["osmatch"][0]["name"])

            # Ports
            for proto in self.scanner[host].all_protocols():
                ports = self.scanner[host][proto].keys()
                for port in ports:
                    state = self.scanner[host][proto][port]["state"]
                    target.add_port(Port(port, state))

            self.results.append(target)

    def save_results(self, filename="scan_results.csv"):
        data = []
        for host in self.results:
            for port in host.ports:
                data.append({
                    "IP": host.ip,
                    "Hostname": host.hostname,
                    "OS": host.os,
                    "Port": port.port_num,
                    "Status": port.status
                })
        df = pd.DataFrame(data)
        df.to_csv(filename, index=False)
        return filename


# ---------------- Flask App ----------------
app = Flask(__name__)
scanner = NmapScanner()

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    target_ip = request.form.get("ip")
    scan_type = request.form.get("scan_type")
    
    scanner.results = []  # reset old results
    scanner.run_scan(target_ip, scan_type)

    results = []
    for host in scanner.results:
        results.append({
            "ip": host.ip,
            "hostname": host.hostname,
            "os": host.os,
            "ports": [{"port": p.port_num, "status": p.status} for p in host.ports]
        })
    
    return jsonify(results)

@app.route("/download")
def download():
    filename = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    filepath = os.path.join(os.getcwd(), filename)
    scanner.save_results(filepath)
    return send_file(filepath, as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True)

