#!/usr/bin/env python3
import sys
import os
import time
import threading
from collections import deque
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Deque, Union

# GUI Imports
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
    QTableView, QTextEdit, QLineEdit, QLabel, QSplitter, 
    QSystemTrayIcon, QMenu, QHeaderView, QAbstractItemView
)
from PyQt6.QtCore import (
    Qt, QThread, pyqtSignal, QAbstractTableModel, QModelIndex, 
    QSortFilterProxyModel, QTimer
)
from PyQt6.QtGui import QIcon, QAction, QTextCursor, QColor, QPalette

import pyqtgraph as pg
import psutil
import pydivert

# ─── REUSE PARSING LOGIC FROM Tls1_monitor.py ──────────────────────────

TLS_VERSION_MAP = {
    b"\x03\x00": "SSLv3", b"\x03\x01": "TLS1.0", b"\x03\x02": "TLS1.1",
    b"\x03\x03": "TLS1.2", b"\x03\x04": "TLS1.3",
}

def safe_decode(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")

def read_u16(data: bytes, off: int) -> int:
    return int.from_bytes(data[off:off + 2], "big")

def read_u24(data: bytes, off: int) -> int:
    return int.from_bytes(data[off:off + 3], "big")

def tls_version_name(version: bytes) -> str:
    return TLS_VERSION_MAP.get(version, f"0x{version.hex()}")

def parse_sni(ext: bytes) -> Optional[str]:
    if len(ext) < 5: return None
    total = read_u16(ext, 0)
    off, end = 2, min(len(ext), 2 + total)
    while off + 3 <= end:
        ntype, nlen = ext[off], read_u16(ext, off + 1)
        off += 3
        if off + nlen > end: break
        if ntype == 0 and nlen: return safe_decode(ext[off:off + nlen])
        off += nlen
    return None

def parse_alpn(ext: bytes) -> List[str]:
    out = []
    if len(ext) < 2: return out
    total = read_u16(ext, 0)
    off, end = 2, min(len(ext), 2 + total)
    while off < end:
        if off + 1 > end: break
        nlen = ext[off]
        off += 1
        if off + nlen > end: break
        if nlen: out.append(safe_decode(ext[off:off + nlen]))
        off += nlen
    return out

def parse_client_hello(body: bytes) -> Optional[Dict]:
    if len(body) < 34: return None
    off = 34 # skip legacy version + random
    sid_len = body[off]
    off += 1 + sid_len
    if off + 2 > len(body): return None
    cs_len = read_u16(body, off)
    off += 2 + cs_len
    if off >= len(body): return None
    comp_len = body[off]
    off += 1 + comp_len
    if off + 2 > len(body): return None
    ext_len = read_u16(body, off)
    off += 2
    end = min(len(body), off + ext_len)
    sni, alpn, versions = None, [], []
    while off + 4 <= end:
        etype, elen = read_u16(body, off), read_u16(body, off + 2)
        off += 4
        if off + elen > end: break
        edata = body[off:off + elen]
        off += elen
        if etype == 0: sni = parse_sni(edata) or sni
        elif etype == 16: alpn = parse_alpn(edata)
    return {"msg": "client_hello", "sni": sni, "alpn": alpn}

# ─── DATA MODELS ──────────────────────────────────────────────────────

@dataclass
class FlowRecord:
    local: str; remote: str; pid: Optional[int] = None; process: str = "unknown"
    sni: Optional[str] = None; alpn: List[str] = field(default_factory=list)
    version: str = "-"; bytes_out: int = 0; bytes_in: int = 0
    last_seen: float = field(default_factory=time.time)
    
    def total_bytes(self): return self.bytes_out + self.bytes_in

class FlowTableModel(QAbstractTableModel):
    def __init__(self):
        super().__init__()
        self.flows: List[FlowRecord] = []
        self.headers = ["Process", "PID", "Remote", "SNI", "TLS", "TX", "RX"]

    def rowCount(self, parent=QModelIndex()): return len(self.flows)
    def columnCount(self, parent=QModelIndex()): return len(self.headers)

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid() or role != Qt.ItemDataRole.DisplayRole: return None
        f = self.flows[index.row()]
        col = index.column()
        if col == 0: return f.process
        if col == 1: return str(f.pid or "-")
        if col == 2: return f.remote
        if col == 3: return f.sni or "-"
        if col == 4: return f.version
        if col == 5: return f"{f.bytes_out / 1024:.1f} KB"
        if col == 6: return f"{f.bytes_in / 1024:.1f} KB"
        return None

    def headerData(self, section, orientation, role):
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return self.headers[section]
        return None

    def update_flow(self, new_f: FlowRecord):
        for i, f in enumerate(self.flows):
            if f.local == new_f.local and f.remote == new_f.remote:
                self.flows[i] = new_f
                self.dataChanged.emit(self.index(i, 0), self.index(i, len(self.headers)-1))
                return
        self.beginInsertRows(QModelIndex(), len(self.flows), len(self.flows))
        self.flows.append(new_f)
        self.endInsertRows()

# ─── CAPTURE THREAD ───────────────────────────────────────────────────

class CaptureWorker(QThread):
    packet_captured = pyqtSignal(object) # Emits FlowRecord
    throughput_update = pyqtSignal(float, float) # out, in bps
    alert_detected = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.running = True
        self.flows: Dict[Tuple[str, str], FlowRecord] = {}
        self.last_tp_check = time.time()
        self.bytes_out_period = 0
        self.bytes_in_period = 0

    def run(self):
        # Sniff all TCP traffic on common TLS ports
        filter_str = "tcp and (tcp.DstPort == 443 or tcp.SrcPort == 443 or tcp.DstPort == 8443)"
        try:
            with pydivert.WinDivert(filter_str, flags=pydivert.Flag.SNIFF) as w:
                for packet in w:
                    if not self.running: break
                    self.process_packet(packet)
        except Exception as e:
            print(f"Capture Error: {e}")

    def process_packet(self, packet):
        is_out = packet.is_outbound
        lip, lport = (packet.src_addr, packet.src_port) if is_out else (packet.dst_addr, packet.dst_port)
        rip, rport = (packet.dst_addr, packet.dst_port) if is_out else (packet.src_addr, packet.src_port)
        key = (f"{lip}:{lport}", f"{rip}:{rport}")
        
        if key not in self.flows:
            self.flows[key] = FlowRecord(local=key[0], remote=key[1])
            # Resolve process name once
            try:
                for conn in psutil.net_connections(kind='tcp'):
                    if conn.laddr.port == lport:
                        self.flows[key].pid = conn.pid
                        self.flows[key].process = psutil.Process(conn.pid).name()
                        break
            except: pass

        f = self.flows[key]
        p_len = len(packet.payload or b"")
        if is_out:
            f.bytes_out += p_len
            self.bytes_out_period += p_len
        else:
            f.bytes_in += p_len
            self.bytes_in_period += p_len
        
        # Simple TLS Alert detection
        if p_len > 0 and packet.payload[0] == 21:
            self.alert_detected.emit(f"TLS Alert from {f.remote} ({f.process})")

        # Parse ClientHello for SNI
        if is_out and p_len > 5 and packet.payload[0] == 22:
            meta = parse_client_hello(packet.payload[5:])
            if meta and meta.get("sni"):
                f.sni = meta["sni"]
                f.alpn = meta.get("alpn", [])

        f.last_seen = time.time()
        self.packet_captured.emit(f)

        # Update throughput stats every 1s
        now = time.time()
        if now - self.last_tp_check >= 1.0:
            dt = now - self.last_tp_check
            self.throughput_update.emit(self.bytes_out_period / dt, self.bytes_in_period / dt)
            self.bytes_out_period = 0
            self.bytes_in_period = 0
            self.last_tp_check = now

# ─── MAIN WINDOW ──────────────────────────────────────────────────────

class TLSMonitorGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Pro TLS Traffic Monitor")
        self.resize(1100, 700)
        
        # 1. Throughput Graph
        self.graph = pg.PlotWidget(title="Real-time Throughput (Bytes/s)")
        self.graph.setBackground('k')
        self.graph.showGrid(x=True, y=True)
        self.graph.addLegend()
        self.out_curve = self.graph.plot(pen=pg.mkPen('b', width=2), name="Upload")
        self.in_curve = self.graph.plot(pen=pg.mkPen('m', width=2), name="Download")
        self.out_data = deque([0]*60, maxlen=60)
        self.in_data = deque([0]*60, maxlen=60)

        # 2. Search and Table
        self.search_bar = QLineEdit()
        self.search_bar.setPlaceholderText("Filter by Process or SNI (e.g. 'google', 'chrome')...")
        
        self.model = FlowTableModel()
        self.proxy_model = QSortFilterProxyModel()
        self.proxy_model.setSourceModel(self.model)
        self.proxy_model.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self.proxy_model.setFilterKeyColumn(-1) # Search all columns
        
        self.table = QTableView()
        self.table.setModel(self.proxy_model)
        self.table.setSortingEnabled(True)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        
        # 3. Details Pane
        self.details = QTextEdit()
        self.details.setReadOnly(True)
        self.details.setPlaceholderText("Select a flow to see detailed handshake metadata...")

        # Layout
        main_layout = QVBoxLayout()
        top_layout = QHBoxLayout()
        top_layout.addWidget(self.graph, stretch=2)
        
        right_panel = QVBoxLayout()
        right_panel.addWidget(QLabel("<b>Detailed Session Info</b>"))
        right_panel.addWidget(self.details)
        top_layout.addLayout(right_panel, stretch=1)

        main_layout.addLayout(top_layout)
        main_layout.addWidget(QLabel("<b>Active TLS Sessions</b>"))
        main_layout.addWidget(self.search_bar)
        main_layout.addWidget(self.table)
        
        container = QWidget()
        container.setLayout(main_layout)
        self.setCentralWidget(container)

        # System Tray
        self.tray = QSystemTrayIcon(self)
        self.tray.setIcon(self.style().standardIcon(QApplication.style().StandardPixmap.SP_ComputerIcon))
        tray_menu = QMenu()
        show_action = QAction("Show", self)
        show_action.triggered.connect(self.showNormal)
        quit_action = QAction("Exit", self)
        quit_action.triggered.connect(QApplication.instance().quit)
        tray_menu.addAction(show_action)
        tray_menu.addAction(quit_action)
        self.tray.setContextMenu(tray_menu)
        self.tray.show()

        # Connect Signals
        self.search_bar.textChanged.connect(self.proxy_model.setFilterFixedString)
        self.table.clicked.connect(self.show_flow_details)
        
        # Start Capture
        self.worker = CaptureWorker()
        self.worker.packet_captured.connect(self.model.update_flow)
        self.worker.throughput_update.connect(self.update_graph)
        self.worker.alert_detected.connect(self.show_alert)
        self.worker.start()

    def update_graph(self, out_bps, in_bps):
        self.out_data.append(out_bps)
        self.in_data.append(in_bps)
        self.out_curve.setData(list(self.out_data))
        self.in_curve.setData(list(self.in_data))

    def show_flow_details(self, index):
        # Get data from the source model via proxy
        row = self.proxy_model.mapToSource(index).row()
        f = self.model.flows[row]
        details = (
            f"<b>Process:</b> {f.process} (PID: {f.pid})<br>"
            f"<b>Remote:</b> {f.remote}<br>"
            f"<b>SNI Domain:</b> <span style='color: #ff00ff;'>{f.sni or 'N/A'}</span><br>"
            f"<b>ALPN Protocols:</b> {', '.join(f.alpn) if f.alpn else 'None'}<br>"
            f"<b>Data Sent:</b> {f.bytes_out / 1024:.2f} KB<br>"
            f"<b>Data Received:</b> {f.bytes_in / 1024:.2f} KB<br>"
            f"<b>Last Activity:</b> {time.ctime(f.last_seen)}"
        )
        self.details.setHtml(details)

    def show_alert(self, msg):
        self.tray.showMessage("TLS Security Alert", msg, QSystemTrayIcon.MessageIcon.Warning)

    def closeEvent(self, event):
        self.worker.running = False
        self.worker.wait()
        event.accept()

if __name__ == "__main__":
    # Check for Admin on Windows (required for pydivert)
    import ctypes
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print("CRITICAL: This application requires Administrative privileges to sniff network traffic.")
        print("Please restart PowerShell/CMD as Administrator.")
        sys.exit(1)

    app = QApplication(sys.argv)
    app.setStyle("Fusion") # Darker, modern look
    
    # Simple Dark Theme
    palette = QColor(53, 53, 53)
    p = app.palette()
    p.setColor(QPalette.ColorRole.Window, palette)
    p.setColor(QPalette.ColorRole.WindowText, Qt.GlobalColor.white)
    p.setColor(QPalette.ColorRole.Base, QColor(25, 25, 25))
    p.setColor(QPalette.ColorRole.AlternateBase, palette)
    p.setColor(QPalette.ColorRole.ToolTipBase, Qt.GlobalColor.white)
    p.setColor(QPalette.ColorRole.ToolTipText, Qt.GlobalColor.white)
    p.setColor(QPalette.ColorRole.Text, Qt.GlobalColor.white)
    p.setColor(QPalette.ColorRole.Button, palette)
    p.setColor(QPalette.ColorRole.ButtonText, Qt.GlobalColor.white)
    p.setColor(QPalette.ColorRole.BrightText, Qt.GlobalColor.red)
    p.setColor(QPalette.ColorRole.Link, QColor(42, 130, 218))
    p.setColor(QPalette.ColorRole.Highlight, QColor(42, 130, 218))
    p.setColor(QPalette.ColorRole.HighlightedText, Qt.GlobalColor.black)
    app.setPalette(p)

    window = TLSMonitorGUI()
    window.show()
    sys.exit(app.exec())
