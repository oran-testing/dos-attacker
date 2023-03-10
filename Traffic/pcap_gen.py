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

def gen_pcap(packets, file_output, random_active, count):
    if random_active:
        for packet in packets:
            packet.src=rand_mac()
            if packets.index(packet) == 0:
                wrpcap(file_output,packet)
            else:
                wrpcap(file_output,packet,append=True,sync=True)

        ## Generation loop
        for i in range (1,count):
            for packet in packets:
                packet.src=rand_mac()
                wrpcap(file_output,packet,append=True,sync=True)
    else:
        for packet in packets:
            if packets.index(packet) == 0:
                wrpcap(file_output,packet)
            else:
                wrpcap(file_output,packet,append=True,sync=True)

        ## Generation loop
        for i in range (1,count):
            for packet in packets:
                wrpcap(file_output,packet,append=True,sync=True) 

    return 1    

if __name__ == "__main__":
    input_pcap =[]
    input_frame_no = []
    packet_list = []
    while True:
        input_sum_packet = int(input("Number of packets   :" ))
        for i in range(0, input_sum_packet):
            input_pcap.append(str(input("File name      : ")))
            input_frame_no.append(int(input("Frame number   : ")))
            # packet_list.append(rdpcap(input_pcap)[input_frame_no])
        
        input_output_name = str(input("Output file name: "))
        input_counter = int(input("Multiplication value: "))

        input_vlan_flag = int(input("Input 1 for VLAN customization: "))
        if input_vlan_flag:
            input_vlan = int(input("New VLAN: "))
        
        print("MAC Address option (1) Follow packet (2) Customize (3) Random source MAC Address")
        mac_opt=int(input("Choice:"))

        if mac_opt==2:
            input_src_mac=str(input("Source: "))
            input_dst_mac=str(input("Destination: "))
        elif mac_opt==3:
            input_dst_mac=str(input("Destination: "))
        elif mac_opt!=1:
            print("Wrong option.")        

        for i in range(0, input_sum_packet):
            print("Loading PCAP files...")
            packet_list.append(rdpcap(input_pcap[i])[input_frame_no[i]])
            packet_list[i].time = 0000000000.000000
            if input_vlan_flag:
                packet_list[i].vlan = input_vlan 
            if mac_opt == 2:
                packet_list[i].src = input_src_mac
                packet_list[i].dst = input_dst_mac
            elif mac_opt == 3:
                packet_list[i].dst = input_dst_mac
        
        if mac_opt==3:
            res=gen_pcap(packet_list,input_output_name,1,input_counter)
        else:
            res=gen_pcap(packet_list,input_output_name,0,input_counter)

        break
