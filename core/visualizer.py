# core/visualizer.py

from rich.console import Console
from rich.table import Table
from rich.bar import Bar
from rich.panel import Panel
from rich.columns import Columns

class TerminalVisualizer:
    """
    Visualizes network traffic statistics using the Rich library in the terminal.
    """
    def __init__(self):
        self.console = Console()
        self.last_lines = 0 # To clear previous output effectively

    def update_display(self, protocol_counts, top_connections, final=False):
        """
        Clears the previous output and prints the updated visualization.
        """
        # Clear previous output
        if not final:
            # Move cursor up and clear lines for dynamic update
            # This is a bit of a hack, a full TUI framework like Textual/Prompt_toolkit
            # would be better for complex real-time updates.
            self.console.clear()
        else:
            self.console.print("\n" * 3) # Add some space before final summary

        self.console.rule("[bold magenta]Network Traffic Summary[/bold magenta]")

        # Protocol Distribution
        protocol_table = Table(
            title="[bold blue]Protocol Distribution[/bold blue]",
            show_header=True, header_style="bold green"
        )
        protocol_table.add_column("Protocol", style="cyan")
        protocol_table.add_column("Count", style="yellow", justify="right")
        protocol_table.add_column("Percentage", style="green", justify="right")

        total_packets = sum(protocol_counts.values())
        if total_packets == 0:
            protocol_table.add_row("N/A", "0", "0.00%")
        else:
            # Sort protocols by count for better visualization
            sorted_protocols = sorted(protocol_counts.items(), key=lambda item: item[1], reverse=True)
            for protocol, count in sorted_protocols:
                percentage = (count / total_packets) * 100
                protocol_table.add_row(
                    protocol,
                    f"{count}",
                    f"{percentage:.2f}%"
                )

        # Top Connections
        connections_table = Table(
            title="[bold blue]Top Connections (Source -> Destination)[/bold blue]",
            show_header=True, header_style="bold green"
        )
        connections_table.add_column("Source IP", style="cyan")
        connections_table.add_column("Destination IP", style="magenta")
        connections_table.add_column("Count", style="yellow", justify="right")

        if not top_connections:
            connections_table.add_row("N/A", "N/A", "0")
        else:
            for src, dst, count in top_connections:
                connections_table.add_row(src, dst, f"{count}")

        # Combine tables into columns for a nicer layout
        self.console.print(
            Columns([
                Panel(protocol_table, border_style="dim blue"),
                Panel(connections_table, border_style="dim blue")
            ])
        )

        if final:
            self.console.rule("[bold magenta]End of Analysis[/bold magenta]")
        else:
            self.console.print("\n[dim]Updating... (Ctrl+C to stop)[/dim]")
