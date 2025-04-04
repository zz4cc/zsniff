import sys
import platform
import time
from enum import Enum
from scapy.all import *
from scapy.layers import http
from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.live import Live
from rich.progress import Progress
from rich.style import Style
from rich.color import Color
import keyboard
import math

class CyberStyle:
    NEON_BLUE = Style(color=Color.parse("#00f3ff"))
    MATRIX_GREEN = Style(color=Color.parse("#00ff00"))
    ERROR_RED = Style(color=Color.parse("#ff003c"))
    WARNING_YELLOW = Style(color=Color.parse("#fff000"))
    DARK_BG = Style(bgcolor=Color.parse("#0a0a12"))
    HEADER_STYLE = Style(bold=True, color="white", bgcolor="bright_black")
    BORDER_STYLE = NEON_BLUE

class CyberMonitor:
    def __init__(self):
        self.console = Console()
        self.layout = Layout()
        self.state = AppState.MAIN_MENU
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
        self.layout["packet_view"].update(
            Panel("", title="[bold]📡 LIVE PACKET STREAM[/]", 
                  border_style=CyberStyle.BORDER_STYLE))
        self.layout["cyber_vis"].update(
            Panel(self._create_radar(), title="[bold]🛰 NETWORK RADAR[/]", 
                 border_style=CyberStyle.BORDER_STYLE))

    def _create_radar(self):
        radar = Text("\n")
        for i in range(1, 6):
            line = " " * 10
            if i % 2 == 0:
                line += "◼" * 3
            else:
                line += "◻" * 3
            line += " " * 5 + str(int(time.time() * 1000) [-3:]
            radar.append(line + "\n", style=CyberStyle.NEON_BLUE)
        return radar

    def _glitch_text(self, text):
        glitch_chars = ["▓", "░", "▒", "▄", "▀"]
        return "".join([c if c != " " else random.choice(glitch_chars) for c in text])

    def _create_header(self):
        header = Text()
        header.append("�" * 40 + "\n", style=CyberStyle.NEON_BLUE)
        title = " CYBER-NET MONITOR v2.3.1 "
        glitched_title = self._glitch_text(title)
        header.append(f"⣾{glitched_title:^38}⣿\n", style=CyberStyle.MATRIX_GREEN)
        header.append("�" * 40 + "\n", style=CyberStyle.NEON_BLUE)
        
        status_line = Text()
        status_line.append("STATUS: ", style="bold")
        status_line.append("ACTIVE" if self.running else "STANDBY", 
                          style="green" if self.running else "red")
        status_line.append(" | THROUGHPUT: ")
        status_line.append(f"{self.stats['throughput']:.1f} pkts/s", 
                          style=CyberStyle.WARNING_YELLOW)
        header.append(status_line)
        
        return Panel(header, style=CyberStyle.DARK_BG)

    def _create_spectrum(self):
        spectrum = Text()
        max_bars = 12
        protocols = ['TCP', 'UDP', 'HTTP', 'DNS', 'OTHER']
        values = [self.stats['tcp'], self.stats['udp'], 
                 self.stats['http'], self.stats['dns'], self.stats['other']]
        
        for proto, val in zip(protocols, values):
            bar = "█" * math.ceil(val / max(1, max(values)) * max_bars
            spectrum.append(f"{proto:5} ", style="bold")
            spectrum.append(f"{bar[:max_bars]} ", style=CyberStyle.NEON_BLUE)
            spectrum.append(f" {val}\n", style="cyan")
        return spectrum

    def _update_cyber_vis(self):
        self.layout["cyber_vis"].update(
            Panel(self._create_radar(), title="[bold]🛰 NETWORK RADAR[/]", 
                 border_style=CyberStyle.BORDER_STYLE))
        
    def _update_packet_view(self):
        packet_table = Table.grid(padding=(0,1))
        packet_table.add_column("No.", style="cyan", width=4)
        packet_table.add_column("Time", style="bright_magenta", width=8)
        packet_table.add_column("Source", style="bright_green", width=20)
        packet_table.add_column("→", style="bold", width=2)
        packet_table.add_column("Destination", style="bright_green", width=20)
        packet_table.add_column("Protocol", style=CyberStyle.WARNING_YELLOW, width=12)
        packet_table.add_column("Info", style="white")

        for idx, pkt in enumerate(self.packets[-15:]):
            style = "reverse" if idx == self.selected_packet else ""
            time_str = f"{pkt.time - self.start_time:07.2f}s"
            src = self._get_source(pkt)
            dst = self._get_destination(pkt)
            proto = self._get_protocol(pkt)
            info = self._get_packet_info(pkt)
            
            packet_table.add_row(
                f"[bold]{idx:03}[/]",
                f"[bright_white]{time_str}[/]",
                f"[green]{src}[/]",
                "[bold]→[/]",
                f"[green]{dst}[/]",
                f"[{self._proto_color(proto)}]{proto}[/]",
                f"[italic]{info}[/]",
                style=style
            )
            
        self.layout["packet_view"].update(
            Panel(packet_table, title="[bold]📡 LIVE PACKET STREAM[/]", 
                 border_style=CyberStyle.BORDER_STYLE))

    def _proto_color(self, proto):
        colors = {
            "TCP": "bright_red",
            "UDP": "bright_blue",
            "HTTP": "bright_yellow",
            "DNS": "bright_magenta",
            "OTHER": "bright_white"
        }
        return colors.get(proto, "white")

    def _create_footer(self):
        footer_grid = Table.grid(expand=True)
        footer_grid.add_column(width=35)
        footer_grid.add_column(width=35)
        
        help_left = Text("\n".join([
            "[bold]↑/↓[/] Navigate packets",
            "[bold]ENTER[/] Inspect packet",
            "[bold]TAB[/] Switch view"
        ]), style=CyberStyle.MATRIX_GREEN)
        
        help_right = Text("\n".join([
            "[bold]F1[/] Capture controls",
            "[bold]F2[/] Protocol filters",
            "[bold]Q[/] Quit system"
        ]), style=CyberStyle.NEON_BLUE)
        
        footer_grid.add_row(help_left, help_right)
        return Panel(footer_grid, style=CyberStyle.DARK_BG)

    def run(self):
        with Live(self.layout, refresh_per_second=10, screen=True) as live:
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
        print(CyberStyle.ERROR_RED + "🚫 SYSTEM ACCESS DENIED - ELEVATE PRIVILEGES")
        sys.exit()

    console = Console()
    with console.status("[bold green]Initializing cyber protocols...", spinner="bouncingBall"):
        time.sleep(2)
        
    monitor = CyberMonitor()
    try:
        monitor.run()
    except KeyboardInterrupt:
        console.print("\n[bold red]🚨 SYSTEM SHUTDOWN INITIATED[/]")