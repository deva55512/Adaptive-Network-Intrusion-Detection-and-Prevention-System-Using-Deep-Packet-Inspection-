from scapy.all import sniff, get_if_list


# Packet handler
def handle_packet(packet):
    try:
        print("Packet captured:", packet.summary())
    except Exception as e:
        print("Packet error:", e)


def start_capture():

    print("Scanning network interfaces...\n")

    interfaces = get_if_list()

    for iface in interfaces:
        print("Interface:", iface)

    interface = interfaces[0]

    print("\nUsing interface:", interface)
    print("Starting packet capture...\n")

    sniff(
        iface=interface,
        prn=handle_packet,
        store=False
    )