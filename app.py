from flask import Flask, request, send_from_directory
from markupsafe import Markup
from utils import scan_port_for_web, scan_udp_port_for_web, scan_stealth_port, get_ttl
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import ipaddress
import os

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def home():
    error_msg = ""
    results = []
    target = ""
    port_list = []

    if request.method == "POST":
        target = request.form.get("target")
        ports = request.form.get("ports")
        scan_type = request.form.get("scan_type")
        use_top_ports = request.form.get("common_ports") == "yes"

        # --- Port Parsing ---
        if use_top_ports:
            try:
                with open("wordlists/common_ports.txt") as f:
                    port_list = [int(line.strip()) for line in f if line.strip().isdigit()]
            except:
                error_msg = "⚠️ Failed to load common ports list."
        else:
            try:
                if "-" in ports:
                    start, end = ports.split("-")
                    port_list = list(range(int(start), int(end) + 1))
                else:
                    port_list = [int(ports)]
            except:
                error_msg = "❌ Invalid port or port range."

        # --- Target Parsing ---
        ip_list = []
        try:
            if '/' in target:
                net = ipaddress.IPv4Network(target, strict=False)
                ip_list = [str(ip) for ip in net.hosts()]
            else:
                ipaddress.IPv4Address(target)
                ip_list = [target]
        except ValueError:
            error_msg = "❌ Invalid IP or CIDR range."

        if not error_msg and len(ip_list) * len(port_list) > 100:
            error_msg = "⚠️ Too many scan targets. Reduce number of IPs or ports."

        # --- Run Scan if No Error ---
        if not error_msg:
            def capture_scan(ip, port):
                if scan_type == "stealth":
                    result = scan_stealth_port(ip, port)
                    if result:
                        results.append(f"{ip}: {result}")
                else:
                    if scan_type in ["tcp", "both"]:
                        result = scan_port_for_web(ip, port)
                        if result:
                            results.append(f"{ip}: {result}")
                    if scan_type in ["udp", "both"]:
                        result = scan_udp_port_for_web(ip, port)
                        if result:
                            results.append(f"{ip}: {result}")

            with ThreadPoolExecutor(max_workers=100) as executor:
                futures = [executor.submit(capture_scan, ip, port) for ip in ip_list for port in port_list]
                for _ in as_completed(futures):
                    pass

            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            filename = f"web_scan_{timestamp}.txt"
            filepath = os.path.join("output", filename)
            os.makedirs("output", exist_ok=True)
            with open(filepath, "w") as f:
                for r in results:
                    f.write(r.replace("<br>", "\n") + "\n")

            # OS Guess
            try:
                ttl = get_ttl(ip_list[0])
                if ttl:
                    if ttl <= 64:
                        os_guess = "Linux/Unix"
                    elif ttl <= 128:
                        os_guess = "Windows"
                    else:
                        os_guess = "Network Device"
                    os_line = f"<p>🧠 OS Guess: <b>{os_guess}</b> (TTL={ttl})</p>"
                else:
                    os_line = ""
            except:
                os_line = ""
        else:
            os_line = ""

        # --- Generate HTML Response ---
        html = f'''
        <html>
        <head>
            <title>Scan Results</title>
            <style>
                body {{
                    font-family: 'Segoe UI', sans-serif;
                    background-color: #1e1e1e;
                    color: #eee;
                    padding: 40px;
                }}
                h2 {{ color: #66d9ef; }}
                .card {{
                    background: #2a2a2a;
                    border: 1px solid #444;
                    padding: 15px;
                    margin-bottom: 15px;
                    border-radius: 8px;
                    font-family: monospace;
                    white-space: pre-wrap;
                }}
                .banner {{
                    background: #111;
                    padding: 10px;
                    margin-top: 8px;
                    border-left: 3px solid #4CAF50;
                    border-radius: 5px;
                    font-size: 14px;
                }}
                .buttons {{
                    margin-top: 30px;
                }}
                a {{
                    color: #4CAF50;
                    text-decoration: none;
                    margin-right: 10px;
                    padding: 10px 15px;
                    border-radius: 5px;
                    background: #333;
                    display: inline-block;
                }}
                a:hover {{ background: #444; }}
                .error {{
                    color: red;
                    font-size: 16px;
                    margin-bottom: 20px;
                }}
            </style>
        </head>
        <body>
            <h2>Scan Results for {target}</h2>
            {f"<div class='error'>{error_msg}</div>" if error_msg else ""}
            {os_line}
        '''

        if not error_msg:
            if results:
                for r in results:
                    html += '<div class="card">'
                    if "Banner:<br>" in r:
                        port_line, banner_html = r.split("Banner:<br>", 1)
                        banner_lines = [line.strip() for line in banner_html.strip().split("<br>") if line.strip()]
                        cleaned_banner = "<br>".join(banner_lines)
                        html += f"{port_line.strip()}<div class='banner'>{cleaned_banner}</div>"
                    else:
                        html += r.strip()
                    html += '</div>'
            else:
                html += '<div class="card">No open ports found.</div>'

            html += f'''
                <div class="buttons">
                    <a href="/download/{filename}" download>⬇️ Download Result File</a>
                    <a href="/">🔙 Back to Scanner</a>
                </div>
            '''
        else:
            html += '''
                <div class="buttons">
                    <a href="/">🔙 Back to Scanner</a>
                </div>
            '''

        html += '</body></html>'
        return Markup(html)

    return '''
        <html>
        <head>
            <title>🛡️ Port Scanner Web</title>
            <style>
                body { font-family: Arial, sans-serif; background-color: #1e1e1e; color: #eee; padding: 40px; }
                input[type=text], select { width: 300px; padding: 8px; font-size: 16px; }
                input[type=submit] { padding: 10px 20px; font-size: 16px; background-color: #4CAF50; color: white; border: none; }
                h2 { color: #66d9ef; }
                form { margin-bottom: 20px; }
                label { font-size: 15px; }
            </style>
        </head>
        <body>
            <h2>🛡️ Port Scanner Web</h2>
            <form method="POST" onsubmit="showLoading()">
                Target IP or CIDR:<br>
                <input type="text" name="target"><br><br>

                Port(s):<br>
                <input type="text" name="ports"><br><br>

                <input type="checkbox" name="common_ports" value="yes"> Use Top Common Ports<br><br>

                Scan Type:<br>
                <select name="scan_type">
                    <option value="tcp">TCP</option>
                    <option value="udp">UDP</option>
                    <option value="both">Both</option>
                    <option value="stealth">Stealth (SYN)</option>
                </select><br><br>

                <input type="submit" value="Start Scan">
            </form>

            <div id="loading" style="display:none;">
                <p>⏳ Scanning... please wait.</p>
            </div>

            <script>
            function showLoading() {
                document.querySelector("form").style.display = "none";
                document.getElementById("loading").style.display = "block";
            }
            </script>
        </body>
        </html>
    '''

@app.route("/download/<filename>")
def download_file(filename):
    return send_from_directory("output", filename, as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True)
