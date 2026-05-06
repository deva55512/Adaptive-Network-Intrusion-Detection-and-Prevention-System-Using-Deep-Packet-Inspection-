from scapy.all import sniff, get_if_list

print("Available interfaces:")
interfaces = get_if_list()
for i, iface in enumerate(interfaces):
    print(f"{i}: {iface}")

iface = interfaces[0]  # change index if needed
print(f"\nUsing interface: {iface}")
print("Sniffing packets (CTRL+C to stop)...\n")

def on_packet(pkt):
    print(pkt.summary())

sniff(iface=iface, prn=on_packet, store=False)
