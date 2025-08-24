# app.py

import argparse
import time
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP, ICMP
from rich import print # Import rich's print for styling
import pandas as pd # Import pandas for CSV export

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
    parser.add_argument(
        "--output-csv", default=None,
        help="Path to CSV file to export results (e.g., results.csv)"
    )
    args = parser.parse_args()

    print(f"[bold green]Starting Network Traffic Visualizer...[/bold green]")
    print(f"Interface: {args.interface if args.interface else 'All available'}")
    print(f"Filter: '{args.filter if args.filter else 'None'}'")
    print(f"Capturing {'infinite' if args.count == 0 else args.count} packets.")
    if args.output_csv:
        print(f"[bold blue]Results will be exported to: {args.output_csv}[/bold blue]")
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

        # Export to CSV if --output-csv argument was provided
        if args.output_csv:
            try:
                protocol_df = packet_processor.get_protocol_df()
                connections_df = packet_processor.get_connections_df()

                with pd.ExcelWriter(args.output_csv, engine='xlsxwriter') as writer:
                    if not protocol_df.empty:
                        protocol_df.to_excel(writer, sheet_name='Protocol_Counts', index=False)
                        print(f"[bold green]Protocol counts exported to '{args.output_csv}' (Sheet: Protocol_Counts)[/bold green]")
                    else:
                        print("[bold yellow]No protocol data to export.[/bold yellow]")

                    if not connections_df.empty:
                        connections_df.to_excel(writer, sheet_name='Top_Connections', index=False)
                        print(f"[bold green]Top connections exported to '{args.output_csv}' (Sheet: Top_Connections)[/bold green]")
                    else:
                        print("[bold yellow]No connection data to export.[/bold yellow]")

                if protocol_df.empty and connections_df.empty:
                    print("[bold yellow]No data was collected, so no CSV file was created.[/bold yellow]")


            except Exception as e:
                print(f"[bold red]Error exporting to CSV: {e}[/bold red]")


if __name__ == "__main__":
    main()
