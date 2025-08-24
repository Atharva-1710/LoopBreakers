# app.py

import argparse
import time
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP, ICMP
from rich import print # Import rich's print for styling

from core.packet_processor import PacketProcessor
from core.visualizer import TerminalVisualizer

def main():
    """
    Main function to parse arguments, capture network traffic,
    process it, and visualize the results.
    """
    parser = argparse.ArgumentParser(
        description="Real-time Network Traffic Visualizer"
    )
    parser.add_argument(
        "-i", "--interface", default=None,
        help="Network interface to sniff on (e.g., eth0, Wi-Fi)"
    )
    parser.add_argument(
        "-c", "--count", type=int, default=0,
        help="Number of packets to capture. 0 means infinite capture."
    )
    parser.add_argument(
        "-f", "--filter", default="",
        help="BPF filter for packet capture (e.g., 'tcp port 80', 'icmp')"
    )
    # Corrected method: parse_args() instead of parse_argument()
    args = parser.parse_args()

    print(f"[bold green]Starting Network Traffic Visualizer...[/bold green]")
    print(f"Interface: {args.interface if args.interface else 'All available'}")
    print(f"Filter: '{args.filter if args.filter else 'None'}'")
    print(f"Capturing {'infinite' if args.count == 0 else args.count} packets.")
    print("\n[bold yellow]Press Ctrl+C to stop.[/bold yellow]\n")

    packet_processor = PacketProcessor()
    visualizer = TerminalVisualizer()

    try:
        # Define a callback function for sniff
        def packet_callback(packet):
            """
            Processes each captured packet and updates the visualizer.
            """
            packet_processor.process_packet(packet)
            # Update visualization periodically or per packet for real-time feel
            # For simplicity, we'll update on every packet for now.
            # In a very high-traffic scenario, you might want to batch updates.
            visualizer.update_display(
                packet_processor.get_protocol_counts(),
                packet_processor.get_top_sources_and_destinations()
            )

        # Start sniffing packets
        # 'store=0' means we don't store packets in memory, processing them on the fly.
        sniff(
            iface=args.interface,
            prn=packet_callback,
            count=args.count,
            filter=args.filter,
            store=0
        )

    except PermissionError:
        print("[bold red]Error: Permission denied. You might need to run this with sudo.[/bold red]")
        print("Try: sudo python3 app.py")
    except ImportError as e:
        print(f"[bold red]Error: Missing module. Please install dependencies.[/bold red]")
        print(f"Details: {e}")
        print("Try: pip install -r requirements.txt")
    except Exception as e:
        print(f"[bold red]An unexpected error occurred: {e}[/bold red]")
    finally:
        print("\n[bold green]Network Traffic Visualizer stopped.[/bold green]")
        # Final display update
        visualizer.update_display(
            packet_processor.get_protocol_counts(),
            packet_processor.get_top_sources_and_destinations(),
            final=True
        )

if __name__ == "__main__":
    main()

