import random
from scapy.all import *

## Random MAC Generator
def rand_mac():
    return "%02x:%02x:%02x:%02x:%02x:%02x" % (
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255)
        )

def random_gen():
    frame_duplicate.src=rand_mac()
    wrpcap("cp_ul_random_10mb_big.pcap",frame_duplicate)

    ## Generation loop
    for i in range (1,6340):
        frame_duplicate.src=rand_mac()
        wrpcap("cp_ul_random_10mb_big.pcap",frame_duplicate,append=True)

    frame_duplicate.src=rand_mac()
    wrpcap("cp_ul_random_1mb_big.pcap",frame_duplicate)

    ## Generation loop
    for i in range (1,634):
        frame_duplicate.src=rand_mac()
        wrpcap("cp_ul_random_1mb_big.pcap",frame_duplicate,append=True)
    return 0

def not_random_gen():
    wrpcap("cp_ul_10mb_big.pcap",frame_duplicate)

    ## Generation loop
    for i in range (1,6340):
        wrpcap("cp_ul_10mb_big.pcap",frame_duplicate,append=True)

    wrpcap("cp_ul_1mb_big.pcap",frame_duplicate)

    ## Generation loop
    for i in range (1,634):
        wrpcap("cp_ul_1mb_big.pcap",frame_duplicate,append=True)
    return 0

if __name__ == "__main__":
    p = rdpcap("/home/fer/Labs/Traffic/cbig_new.pcap")
    frame_duplicate=p[483]
    frame_duplicate.vlan=1

    vlan_input=int(input("VLAN:"))
    frame_duplicate.vlan=vlan_input

    print("MAC Address option (1) Default (2) Customize (3) Random")
    mac_opt=int(input("Choice:"))

    if mac_opt==1:
        frame_duplicate.src="00:01:07:11:21:12"
        frame_duplicate.dst="00:01:07:36:00:03"
        res=not_random_gen()
    elif mac_opt==2:
        frame_duplicate.src=str(input("Source:"))
        frame_duplicate.dst=str(input("Destination:"))
        res=not_random_gen()
    elif mac_opt==3:
        frame_duplicate.dst="00:01:07:36:00:03"
        res=random_gen()
    else:
        print("Wrong option.")