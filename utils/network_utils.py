# utils/network_utils.py

import socket

def get_local_ip_address():
    """
    Attempts to get the local machine's primary IP address.
    This method is not foolproof but works for many common setups.
    """
    try:
        # Create a UDP socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Connect to an external host (doesn't actually send data)
        # This forces the OS to choose the most appropriate local IP
        s.connect(("8.8.8.8", 80))
        ip_address = s.getsockname()[0]
        s.close()
        return ip_address
    except Exception:
        return "127.0.0.1" # Fallback to loopback if an error occurs

def resolve_hostname(ip_address):
    """
    Resolves an IP address to a hostname, if possible.
    Returns the IP address if hostname resolution fails.
    """
    try:
        return socket.gethostbyaddr(ip_address)[0]
    except socket.herror:
        return ip_address # Return IP if hostname not found

# You can add more utility functions here as your project grows,
# such as functions to list active interfaces (though Scapy handles this well),
# or to perform port scanning, etc.

