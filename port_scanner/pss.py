from flask import Flask, request, render_template
import os
import json
import socket
import re

app = Flask(__name__)
PROBES_FOLDER = "probes_list"
PORTS = [21, 22, 23, 25, 53, 67, 68, 69, 70, 79, 80, 88, 110, 119, 123, 135, 137, 138, 139, 143, 161, 179, 194, 389, 443, 445, 514, 520, 548, 636, 993, 995, 1352, 1433, 1521, 1720, 1723, 1812, 1813, 1900, 3306, 3389, 5432, 8080, 8443, 8888]

def load_probes(probes_folder):
    probes = []
    for filename in os.listdir(probes_folder):
        if filename.endswith(".json"):
            with open(os.path.join(probes_folder, filename), 'r') as file:
                probes.append(json.load(file))
    return probes

def is_port_open(target, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)  
    result = sock.connect_ex((target, port))
    sock.close()
    return result == 0

def send_probe(target, port, probe):
    response = ""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((target, port))
        
        probe = probe.replace("{{target}}", target)
        
        sock.sendall(probe.encode())
        response = sock.recv(4096).decode()
        sock.close()
    except Exception as e:
        response = f"Error: {e}"
    return response

def match_response(response, patterns):
    for pattern in patterns:
        if re.match(pattern["regex"], response):
            return pattern["service"]
    return "Unknown service"

def service_scan(target, ports, probes):
    open_ports = [port for port in ports if is_port_open(target, port)]
    results = []
    for port in open_ports:
        for probe in probes:
            if port in probe["ports"]:
                response = send_probe(target, port, probe["probe"])
                if response:
                    service = match_response(response, probe["patterns"])
                    results.append({"port": port, "service": service})
                    break
    return results

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    target = request.form['target']
    probes = load_probes(PROBES_FOLDER)
    results = service_scan(target, PORTS, probes)
    return render_template('results.html', target=target, results=results)

if __name__ == '__main__':
    if not os.path.exists(PROBES_FOLDER):
        os.makedirs(PROBES_FOLDER)
    app.run(host='0.0.0.0', port=5000, debug=True)

