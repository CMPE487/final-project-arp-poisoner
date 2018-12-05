from Sniffer import Sniffer



if __name__== "__main__":
    sniffer = Sniffer("192.168.1.100")
    sniffer.sniff_packets(1000)


