from scapy.all import sniff

def monitor_packet(packet):
    # Check if the packet has a payload
    if packet.haslayer('Raw'):
        payload_length = len(packet['Raw'].load)
        if payload_length > 1500:  # Adjust this value as needed
            print(f"Alert! Large amount of data is being uploaded or downloaded. Payload length: {payload_length}")

# Start sniffing packets
sniff(prn=monitor_packet)
