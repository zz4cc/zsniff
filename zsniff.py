import sys
import platform
import time
import random
import math
from enum import Enum
from queue import Queue, Empty
from scapy.all import *
from scapy.layers import http
from rich.console import Console, Style
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.live import Live
import keyboard
import ctypes
from threading import Thread

class CyberStyle:
    NEON_BLUE = Style(color="#00f3ff")
    MATRIX_GREEN = Style(color="#00ff00")
    ERROR_RED = Style(color="#ff003c")
    WARNING_YELLOW = Style(color="#fff000")
    DARK_BG = Style(bgcolor="#0a0a12")
    HEADER_STYLE = Style(bold=True, color="white", bgcolor="bright_black")
    BORDER_STYLE = NEON_BLUE

class CyberMonitor:
    def __init__(self):
        self.console = Console()
        self.layout = Layout()
        self.packets = []
        self.selected_packet = 0
        self.interface = None
        self.filter_exp = None
        self.capture_thread = None
        self.running = False
        self.packet_queue = Queue()
        self.stats = {
            'total': 0, 'tcp': 0, 'udp': 0,
            'http': 0, 'dns': 0, 'other': 0,
            'throughput': 0
        }
        self._setup_cyber_layout()
        self._setup_keybinds()
        self.start_time = time.time()

    def _setup_cyber_layout(self):
        self.layout.split(
            Layout(name="header", size=5),
            Layout(name="main", ratio=1),
            Layout(name="footer", size=4)
        )
        self.layout["main"].split_row(
            Layout(name="packet_view", ratio=2),
            Layout(name="cyber_vis", ratio=1)
        )

    def _create_radar(self):
        radar = Text("\n")
        symbols = ["◼", "◻", "✦", "✧", "⌘"]
        for i in range(6):
            line = " " * 10
            line += random.choice(symbols) * 3
            line += " " * 5 + str(int(time.time() * 1000))[-3:]
            radar.append(line + "\n", style=CyberStyle.NEON_BLUE)
        return radar

    def _glitch_text(self, text):
        glitch_chars = ["▓", "░", "▒", "▄", "▀"]
        return "".join([c if c != " " else random.choice(glitch_chars) for c in text])

    def _create_header(self):
        header = Text()
        header.append("▞" * 40 + "\n", style=CyberStyle.NEON_BLUE)
        title = " CYBER-NET MONITOR v2.3.1 "
        header.append(f"⣾{self._glitch_text(title):^38}⣿\n", style=CyberStyle.MATRIX_GREEN)
        header.append("▚" * 40 + "\n", style=CyberStyle.NEON_BLUE)
        
        status_line = Text()
        status_line.append("STATUS: ", style="bold")
        status_line.append("ACTIVE" if self.running else "STANDBY", 
                          style="green" if self.running else "red")
        status_line.append(" | THROUGHPUT: ")
        status_line.append(f"{self.stats['throughput']:.1f} pkts/s", 
                          style=CyberStyle.WARNING_YELLOW)
        return Panel(header, style=CyberStyle.DARK_BG)

    def _create_spectrum(self):
        spectrum = Text()
        max_bars = 12
        protocols = ['TCP', 'UDP', 'HTTP', 'DNS', 'OTHER']
        values = [self.stats['tcp'], self.stats['udp'], 
                 self.stats['http'], self.stats['dns'], self.stats['other']]
        max_val = max(values) if max(values) > 0 else 1
        
        for proto, val in zip(protocols, values):
            bar_length = math.ceil((val / max_val) * max_bars)
            bar = "█" * bar_length
            spectrum.append(f"{proto:5} ", style="bold")
            spectrum.append(f"{bar:{max_bars}} ", style=CyberStyle.NEON_BLUE)
            spectrum.append(f" {val}\n", style="cyan")
        return spectrum

    def _update_cyber_vis(self):
        vis_content = Table.grid()
        vis_content.add_row(self._create_radar())
        vis_content.add_row(Panel(self._create_spectrum(), title="PROTOCOL SPECTRUM"))
        self.layout["cyber_vis"].update(
            Panel(vis_content, title="🛰 NETWORK RADAR", 
                 border_style=CyberStyle.BORDER_STYLE))

    def _setup_keybinds(self):
        keyboard.add_hotkey('esc', lambda: sys.exit())  # Press ESC to exit

    def capture_packets(self):
        def packet_callback(pkt):
            self.packets.append(pkt)
            if isinstance(pkt, IP):
                if pkt.haslayer(TCP):
                    self.stats['tcp'] += 1
                elif pkt.haslayer(UDP):
                    self.stats['udp'] += 1
                elif pkt.haslayer(http.HTTPRequest):
                    self.stats['http'] += 1
                elif pkt.haslayer(DNS):
                    self.stats['dns'] += 1
                else:
                    self.stats['other'] += 1

        sniff(prn=packet_callback, store=0, filter=self.filter_exp, iface=self.interface)

    def run(self):
        self.capture_thread = Thread(target=self.capture_packets, daemon=True)
        self.capture_thread.start()

        with Live(self.layout, refresh_per_second=10, screen=True):
            while True:
                self._process_packets()
                self.stats['throughput'] = len(self.packets) / (time.time() - self.start_time)
                
                self.layout["header"].update(self._create_header())
                self.layout["footer"].update(self._create_footer())
                self._update_packet_view()
                self._update_cyber_vis()
                
                time.sleep(0.1)

if __name__ == "__main__":
    if platform.system() == 'Windows' and not ctypes.windll.shell32.IsUserAnAdmin():
        print("🚫 SYSTEM ACCESS DENIED - RUN AS ADMINISTRATOR")
        sys.exit()

    monitor = CyberMonitor()
    try:
        monitor.run()
    except KeyboardInterrupt:
        print("\n[bold red]🚨 SYSTEM SHUTDOWN INITIATED[/]")  
