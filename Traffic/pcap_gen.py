import random
from scapy.all import *



ECPRI_MESSAGE_TYPE = {
    0x00: "IQ Data", 
    0x02: "Real-time Control Data"
}

EXTENSION_FLAG = {
    0: "no Section Extensions",
    1: "one or more Section Extensions are included in this section"
}

DATA_DIRECTION ={
    0: "Uplink",
    1: "Downlink"
}

SECTION_TYPES = {
    0: "Unused Resource Blocks or symbols in Downlink or Uplink",
    1: "Most DL/UL radio channels",
    2: "Reserved",
    3: "PRACH and mixed-numerology channels",
    4: "Reserved",
    5: "UE scheduling information",
    6: "Channel information",
    7: "LAA"
}

class bfw(Packet):
  name = "TRX"
  fields_desc = [
                    XBitField("bfwI", None, 8),
                    XBitField("bfwQ", None,  8)
                  ]
  def extract_padding(self, p):
        return "", p

class extension(Packet):
  name = "extension"
  fields_desc = [
                    BitField("ef", None, 1),
                    BitField("exType", None,  7),
                    ByteField("extLen", None),
                    BitField("bfwCompHdr_iqWidth", None, 4),
                    BitField("bfwCompHdr_compMeth", None, 4),
                    ByteField("exponent", None),
                    PacketListField("bfw",None,bfw,count_from=lambda pkt:10)
                  ]
  def extract_padding(self, p):
        return "", p

# class extension_link(Packet):
#   name = "extension"
#   fields_desc = [
#                     PacketListField("extension",None,extension,count_from=lambda pkt:section.numPrbc)
#                   ]
#   def extract_padding(self, p):
#         return "", p

class prb(Packet):
  name = "TRX"
  fields_desc = [
                    BitField("reserved", None, 4),
                    BitField("exponent", None,  4),
                    BitField("iq_user_data", None, 336)
                  ]
  def extract_padding(self, p):
        return "", p


class section_u(Packet):
    name = "section_u"
    fields_desc = [
                    BitField("sectionId", None, 12),
                    BitField("rb", None,  1),
                    BitField("symInc", None, 1),
                    BitField("startPrbc", 64, 10),
                    ByteField("numPrbc", 26),
                    PacketListField("prb",None,prb,count_from=lambda pkt:pkt.numPrbc)
                  ]
    def extract_padding(self, p):
        return "", p

class section(Packet):
    name = "section"
    fields_desc = [
                    BitField("sectionId", None, 12),
                    BitField("rb", None,  1),
                    BitField("symInc", None, 1),
                    BitField("startPrbc", 64, 10),
                    ByteField("numPrbc", 26),
                    XBitField("reMask", 0xfff, 12),
                    BitField("numSymbol", 14, 4),
                    BitEnumField("ef", 1, 1, EXTENSION_FLAG),
                    BitField("beamId", 1, 15),
                    PacketListField("extension",None,extension,count_from=lambda pkt:pkt.numPrbc)
                  ]
    def extract_padding(self, p):
        return "", p

class u_plane(Packet):
    name = "u_plane"
    fields_desc = [
                    BitEnumField("dataDirection", 0, 1, DATA_DIRECTION),
                    BitField("payloadVersion", 1, 3),
                    BitField("filterIndex", 0, 4),
                    ByteField("frameId", 0),
                    BitField("subframeId", 0, 4),
                    BitField("slotID", 0, 6),
                    BitField("startSymbolId", 0, 6)
                  ]
    def extract_padding(self, p):
        return "", p

class c_plane(Packet):
    name = "c_plane"
    fields_desc = [
                    BitEnumField("dataDirection", 0, 1, DATA_DIRECTION),
                    BitField("payloadVersion", 1, 3),
                    BitField("filterIndex", 0, 4),
                    ByteField("frameId", 0),
                    BitField("subframeId", 0, 4),
                    BitField("slotID", 0, 6),
                    BitField("startSymbolId", 0, 6),
                    ByteField("numberOfsections", 1),
                    ByteEnumField("sectionType", 1, SECTION_TYPES),
                    ByteField("udCompHdr", 0),
                    ByteField("reserved", 0),
                  ]
    def extract_padding(self, p):
        return "", p

class ecpriSeqid(Packet):
    name = "ecpriSeqid"
    fields_desc = [
                    ByteField("sequence_id", 135),
                    BitField("e_bit", 1, 1),
                    BitField("subsequence_id", 0, 7)
                  ]
    def extract_padding(self, p):
        return "", p

class ecpriRtcid(Packet):
    name = "ecpriRtcid"
    fields_desc = [
                    BitField("du_port_id", 2, 2),
                    BitField("bandsector_id", 4, 6),
                    BitField("cc_id", 2, 4),
                    BitField("ru_port_id", 2, 4)
                  ]
    def extract_padding(self, p):
        return "", p    

class o_ran_fh_u(Packet):
    name = "o_ran_fh_u"
    fields_desc=[ 
                  PacketField("ecpriRtcid","",ecpriRtcid),
                  PacketField("ecpriSeqid","",ecpriSeqid),
                  PacketField("u_plane","",u_plane),
                  PacketListField("section",None,section_u, count_from=lambda pkt:273)
                  # PacketField("section","",section),
                  # PacketListField("extension",None,extension,count_from=lambda pkt:pkt.section.numPrbc)
                 ]
    def extract_padding(self, p):
        return "", p  

class o_ran_fh_c(Packet):
    name = "o_ran_fh_c"
    fields_desc=[ 
                  PacketField("ecpriRtcid","",ecpriRtcid),
                  PacketField("ecpriSeqid","",ecpriSeqid),
                  PacketField("c_plane","",c_plane),
                  PacketListField("section",None,section, count_from=lambda pkt:pkt.c_plane.numberOfsections)
                  # PacketField("section","",section),
                  # PacketListField("extension",None,extension,count_from=lambda pkt:pkt.section.numPrbc)
                 ]
    def extract_padding(self, p):
        return "", p   

class eCPRI(Packet):
    name = "ecpri"
    fields_desc=[ BitField("revision",1,4),
                 BitField("reserved",0,3) ,
                 BitField("cbit",0,1),
                 XByteEnumField("type", 0x02, ECPRI_MESSAGE_TYPE),
                 ShortField("size", 644)
                 # PacketListField("o_ran_fh_c","",o_ran_fh_c)
                 ]

bind_layers(eCPRI, o_ran_fh_u, {'type':0x00})
bind_layers(eCPRI, o_ran_fh_c, {'type':0x02})
bind_layers(Dot1Q,eCPRI, type=0xaefe)

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

def gen_pcap(file_output, random_active, count):
    if random_active:
        frame_duplicate.src=rand_mac()
        wrpcap(file_output,frame_duplicate)

        ## Generation loop
        for i in range (1,count):
            frame_duplicate.src=rand_mac()
            wrpcap(file_output,frame_duplicate,append=True)
    else:
        wrpcap(file_output,frame_duplicate)

        ## Generation loop
        for i in range (1,count):
            wrpcap(file_output,frame_duplicate,append=True)    
    return 1    


# def random_gen():
#     frame_duplicate.src=rand_mac()
#     wrpcap("cp_ul_random_10mb_big.pcap",frame_duplicate)

#     ## Generation loop
#     for i in range (1,6340):
#         frame_duplicate.src=rand_mac()
#         wrpcap("cp_ul_random_10mb_big.pcap",frame_duplicate,append=True)

#     frame_duplicate.src=rand_mac()
#     wrpcap("cp_ul_random_1mb_big.pcap",frame_duplicate)

#     ## Generation loop
#     for i in range (1,634):
#         frame_duplicate.src=rand_mac()
#         wrpcap("cp_ul_random_1mb_big.pcap",frame_duplicate,append=True)
#     return 0

# def not_random_gen():
#     wrpcap("cp_ul_10mb_big.pcap",frame_duplicate)

#     ## Generation loop
#     for i in range (1,6340):
#         wrpcap("cp_ul_10mb_big.pcap",frame_duplicate,append=True)

#     wrpcap("cp_ul_1mb_big.pcap",frame_duplicate)

#     ## Generation loop
#     for i in range (1,634):
#         wrpcap("cp_ul_1mb_big.pcap",frame_duplicate,append=True)
#     return 0

if __name__ == "__main__":
    file_input = str(input("PCAP file: "))
    print("Reading "+file_input)
    p = rdpcap(file_input)
    print("Finished reading file.")
    seq = int(input("Frame number: "))
    frame_duplicate=p[seq]

    print("Reading "+ file_input)
    frame_duplicate.show2

    output_name=str(input("Output file name: "))

    counter=int(input("Number of packet in PCAP: "))

    print("VLAN option (1) Follow packet (2) Custom")
    vlan_opt=int(input("Choice: "))
    if vlan_opt==2:
        vlan_input=int(input("Desired VLAN: "))
        frame_duplicate.vlan=vlan_input

    print("MAC Address option (1) Follow packet (2) Customize (3) Random source MAC Address")
    mac_opt=int(input("Choice:"))


    if mac_opt==1:
        res=gen_pcap(output_name,0,counter)
    elif mac_opt==2:
        frame_duplicate.src=str(input("Source: "))
        frame_duplicate.dst=str(input("Destination: "))
        res=gen_pcap(output_name,0,counter)
    elif mac_opt==3:
        frame_duplicate.dst=str(input("Destination: "))
        res=gen_pcap(output_name,1,counter)
    else:
        print("Wrong option.")

if res:
    print(output_name+" generated.")
else:
    print("PCAP generation failed.")