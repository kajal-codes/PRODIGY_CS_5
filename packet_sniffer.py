import streamlit as st
import pandas as pd
from scapy.all import sniff, IP, TCP, UDP
import threading

# Global variables
captured_packets = []
sniffing = False

# Packet processing function
def packet_handler(packet):
    if IP in packet:
        data = {
            "Source IP": packet[IP].src,
            "Destination IP": packet[IP].dst,
            "Protocol": "TCP" if TCP in packet else "UDP" if UDP in packet else "Other",
            "Length": len(packet)
        }
        captured_packets.append(data)

# Sniffing function
def start_sniffing():
    global sniffing
    sniffing = True
    sniff(prn=packet_handler, store=False, filter="ip", timeout=30)

# Stop sniffing function
def stop_sniffing():
    global sniffing
    sniffing = False

# Streamlit UI
st.title("🔍 Network Packet Sniffer")
st.info("Click 'Start Sniffing' to capture network packets. Run as Administrator.")

# Start/Stop Buttons
col1, col2 = st.columns(2)
with col1:
    if st.button("🚀 Start Sniffing", use_container_width=True):
        captured_packets.clear()
        sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
        sniff_thread.start()
        st.success("Sniffing started...")

with col2:
    if st.button("⛔ Stop Sniffing", use_container_width=True):
        stop_sniffing()
        st.warning("Sniffing stopped.")

# Display Captured Packets
st.subheader("📊 Captured Packets")
packets_placeholder = st.empty()

while sniffing:
    if captured_packets:
        df = pd.DataFrame(captured_packets, columns=["Source IP", "Destination IP", "Protocol", "Length"])
        packets_placeholder.dataframe(df, height=300)
