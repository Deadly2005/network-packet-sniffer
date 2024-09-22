import os
import sys
import subprocess
import logging
import argparse
import time
import threading
from datetime import datetime
from scapy.all import sniff, wrpcap
from collections import deque
import plotly.graph_objects as go
from plotly.subplots import make_subplots

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Initialize buffers
packet_timestamps = deque()
packet_details = []
max_buffer_size = 1000
output_dir = None

def install_or_update_package(package):
    """Install or update a package using pip."""
    try:
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', '--upgrade', package])
        logging.info(f"{package} installed/updated successfully.")
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to install/update {package}. Error: {e}")
        sys.exit(1)

def check_dependencies():
    """Check and install/update required packages."""
    required_packages = ["scapy", "plotly"]
    for package in required_packages:
        try:
            __import__(package)
            logging.info(f"{package} is already installed.")
        except ImportError:
            logging.info(f"{package} not found. Installing...")
            install_or_update_package(package)

def get_network_interface():
    """Get the network interface selected by the user."""
    from scapy.all import get_if_list
    interfaces = get_if_list()
    if not interfaces:
        logging.error("No network interfaces found.")
        sys.exit(1)
    
    print("Available network interfaces:")
    for idx, iface in enumerate(interfaces):
        print(f"{idx + 1}. {iface}")
    
    choice = int(input("Select the network interface to use (by number): ")) - 1
    if choice < 0 or choice >= len(interfaces):
        logging.error("Invalid choice. Exiting.")
        sys.exit(1)
    
    selected_interface = interfaces[choice]
    logging.info(f"Selected network interface: {selected_interface}")
    return selected_interface

def packet_callback(packet):
    """Capture and process each packet."""
    packet_timestamps.append(time.time())
    packet_details.append(packet)
    if len(packet_timestamps) > max_buffer_size:
        packet_timestamps.popleft()
        packet_details.pop(0)

def write_to_pcap():
    """Write the buffered packets to a pcap file."""
    if output_dir:
        pcap_file = os.path.join(output_dir, 'network_traffic.pcap')
        os.makedirs(output_dir, exist_ok=True)
    else:
        pcap_file = 'network_traffic.pcap'

    # Convert the buffer to a list of Scapy packets
    packets_to_save = [pkt for pkt in packet_details]
    
    try:
        if packets_to_save:
            wrpcap(pcap_file, packets_to_save)
            logging.info(f"Saved {len(packets_to_save)} packets to {pcap_file}")
        else:
            logging.info("No packets to save.")
    except Exception as e:
        logging.error(f"Failed to write packets to pcap file. Error: {e}")

def sniff_packets(duration, interface):
    """Capture packets for a specified duration."""
    logging.info("Starting packet sniffing...")
    sniff(iface=interface, prn=packet_callback, timeout=duration)
    logging.info("Packet sniffing completed.")
    write_to_pcap()

def visualize_traffic():
    """Create interactive visualizations from the captured packets."""
    if not packet_timestamps:
        logging.info("No packets captured. No data to visualize.")
        return
    
    # Convert timestamps to relative time
    start_time = packet_timestamps[0]
    relative_times = [t - start_time for t in packet_timestamps]
    
    # Create a figure
    fig = go.Figure()
    
    # Packet count over time
    fig.add_trace(go.Histogram(
        x=relative_times,
        nbinsx=30,
        name="Packet Count",
        marker_color='royalblue'
    ))
    
    # Update layout
    fig.update_layout(
        title_text="Network Traffic Analysis Over Time",
        xaxis_title="Time Since Start (seconds)",
        yaxis_title="Number of Packets",
        xaxis=dict(
            title='Time (seconds)',
            titlefont=dict(size=14, color='rgb(107,107,107)'),
            tickfont=dict(size=12, color='rgb(107,107,107)')
        ),
        yaxis=dict(
            title='Number of Packets',
            titlefont=dict(size=14, color='rgb(107,107,107)'),
            tickfont=dict(size=12, color='rgb(107,107,107)')
        ),
        height=600,
        width=800,
        plot_bgcolor='white',
        paper_bgcolor='lightgray',
        font=dict(size=12)
    )
    
    # Save and display the plot
    if output_dir:
        fig.write_html(os.path.join(output_dir, 'network_traffic_analysis.html'))
    else:
        fig.show()

def handle_signal(signal, frame):
    """Handle interruption signals."""
    logging.info("Interrupt signal received. Saving buffered packets before exiting...")
    if packet_timestamps:
        write_to_pcap()
    sys.exit(0)

def main():
    """Main function."""
    global output_dir
    check_dependencies()

    parser = argparse.ArgumentParser(description='Network Traffic Analysis Tool')
    parser.add_argument('-t', '--time', required=True, type=int, help='Time duration to capture packets (in seconds)')
    parser.add_argument('-o', '--output', required=False, help='Output directory for visualizations')
    args = parser.parse_args()

    capture_time = args.time
    output_dir = args.output

    import signal
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    interface = get_network_interface()

    sniff_thread = threading.Thread(target=sniff_packets, args=(capture_time, interface))
    sniff_thread.start()
    
    sniff_thread.join()
    
    logging.info("Packet capture complete. Starting data visualization...")
    visualize_traffic()
    logging.info("Data visualization complete.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logging.info("\nStopping packet sniffing...")
        if packet_timestamps:
            write_to_pcap()
        visualize_traffic()

