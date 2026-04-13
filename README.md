🖥️ TLS Traffic Monitor (GUI)
A desktop TLS/SSL traffic monitor for Windows with a live graph, searchable flow table, and session details pane.
✨ Features
📊 Real-time throughput graph
🔍 Search/filter by process or SNI
🧾 Active TLS session table
🔎 Detailed session metadata pane
🚨 TLS alert notifications in the system tray
👤 Process attribution with `psutil`
🌐 TLS handshake parsing for SNI and ALPN
> ⚠️ This tool is passive only. It does **not** decrypt TLS payloads.
---
🛠️ Requirements
Windows 10/11
Python 3.10+
Administrator privileges
WinDivert driver installed
Dependencies from `requirements.txt`
---
📦 Installation
```powershell
git clone <your-repo-url>
cd <your-repo-folder>
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
```
WinDivert
`pydivert` needs the WinDivert driver to sniff packets. Install WinDivert separately before running the GUI.
---
🚀 Usage
Run from an elevated PowerShell:
```powershell
python Tls1_monitor_gui.py
```
---
🧩 Interface Guide
1. Graph Area
Shows live upload and download throughput in bytes per second.
2. Search Box
Filter sessions by process name, domain, or any visible field.
3. Active TLS Sessions
Shows:
Process name
PID
Remote host
SNI
TLS version
TX / RX totals
4. Detailed Session Info
Select a row to view richer metadata about that flow.
5. System Tray
Displays TLS alerts and lets you keep the app running in the background.
---
📁 File
`Tls1_monitor_gui.py` — GUI TLS monitor
---
🤝 Notes
Best used with administrative access
Windows-only because it depends on WinDivert, PyQt6, and live packet capture
Useful for blue-team monitoring, investigation, and lab work
