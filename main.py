from threading import *
from Window1 import FirstWindow
from Window2 import SecondWindow
from database import DATABASE
import sys
from scapy.all import *
import socket
import datetime
import os
import time
from uuid import uuid4



#------------------------------------ Display the first window --------------------------------------

app1=FirstWindow.Q_App()
window1=FirstWindow()

#------------------------------------ Display the second window -------------------------------------

open_window=False

def click():
    global open_window
    window1.close()
    open_window=True

window1.pushButton.clicked.connect(click)
app1.exec_()

if open_window:
    app2=SecondWindow.Q_App()
window2=SecondWindow()







#------------------------------------------ Buttons Set -----------------------------------------------

def stop_sniffer(pkt):
    global should_we_stop
    return should_we_stop


def sniffing():
    sniff(prn=sniffer,stop_filter=stop_sniffer)


def start_sniffing():
    global should_we_stop
    global thread
    global pcap_item
    global is_pcap
    is_pcap="1"
    if (thread is None) or (not thread.is_alive()):
        should_we_stop = False
        clear(pcap_item)
        clear(filter_list)
        thread = threading.Thread(target=sniffing)
        thread.start()


def stop_sniffing():

    global should_we_stop
    should_we_stop = True


thread = None
should_we_stop = True
is_pcap=None

def open_file():
    global should_we_stop
    global j
    global packet_list
    global pcap_list
    should_we_stop = True
    pcap_list= []
    if packet_list:
        choice = window2.ask_to_save()
        if choice == "Yes":
            save_file()
        else:
            packet_list=[]
    try:
        response=window2.getFileName()
        clear(item_list)
        clear(pcap_item)
        clear(filter_list)
        j=1
        sniff(offline=response, prn=read_pcap,store=0)
    except Exception:
        return None

def save_file():
    global should_we_stop
    global packet_list
    should_we_stop=True
    window2.file_save(packet_list)
    packet_list=[]

filter_list=[]
def filtering():
    global should_we_stop
    global is_pcap
    global filter_list
    is_pcap="2"
    should_we_stop=True
    color_dict={"TCP":"#E0FFFF","UDP":"#FAFAD2","ICMP":"#FFF0F5"}
    clear(item_list)
    clear(filter_list)
    clear(pcap_item)
    try:
        i=1
        for row in window2.get_text():
            new_row=[]
            new_row.append(str(i))
            i+=1
            for e in row[1:-1]:
                new_row.append(str(e))
            filter_list.append(window2.add_packet(new_row,color_dict[row[-1]]))
    except Exception as e:
        print(e)


def onItemClicked(it):
    global pcap_list
    global packet_list
    global is_pcap
    index=int(it.text(0))
    sys.stdout=open('show.txt','w')
    if  is_pcap == "0":
        pcap_list[index-1].show()
    elif is_pcap == "1":
        packet_list[index-1].show()
    else:
        return None
    sys.stdout.close()
    f=open('show.txt','r')
    pshow=f.read()
    f.close()
    sys.stdout=open('hex.txt','w')
    if is_pcap == "0":
        hexdump(pcap_list[index-1])
    elif is_pcap == "1":
        hexdump(packet_list[index-1])
    else:
        return None
    sys.stdout.close()
    d=open('hex.txt','r')
    phex=d.read()
    d.close()
    window2.OpenInfo(pshow,phex)
    os.remove('hex.txt')
    os.remove('show.txt')


window2.Start.clicked.connect(start_sniffing)
window2.actionStart.triggered.connect(start_sniffing)
window2.Stop.clicked.connect(stop_sniffing)
window2.actionStop.triggered.connect(stop_sniffing)
window2.Open.clicked.connect(open_file)
window2.actionOpen.triggered.connect(open_file)
window2.Save.clicked.connect(save_file)
window2.actionSave.triggered.connect(save_file)
window2.Filter.clicked.connect(filtering)
window2.actionHelp.triggered.connect(window2.OpenHelp)
window2.PacketTable.itemClicked.connect(lambda x :onItemClicked(x))














#------------------------------------ sniffer script ------------------------------------------------

def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Doesn't even have to be reachable
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP    

i=1
Id=1
item_list=[]
packet_list=[]

def sniffer(pkt):

    global i
    global item_list
    global packet_list
    time=datetime.datetime.now()
    date=time.strftime("%Y")+"-"+time.strftime("%m")+"-"+time.strftime("%d")
    packet=[]
    data=DATABASE()

    # Classifying packets into TCP
    if pkt.haslayer(TCP):
        # Classifying packets into TCP Incoming packets
        if get_ip()== pkt[IP].dst or get_ip()== pkt[IP].src:
            packet.append(str(i))
            packet.append(str(time))
            packet.append(str(len(pkt[TCP])))
            packet.append(str(pkt.src))
            packet.append(str(pkt.dst))
            packet.append(str(pkt[IP].src))
            packet.append(str(pkt[IP].dst))
            packet.append(str(pkt.sport))
            packet.append(str(pkt.dport))
            try:
                packet.append(socket.getservbyport(pkt.sport))
            except Exception:
                try:
                    packet.append(socket.getservbyport(pkt.dport))
                except Exception:
                    packet.append("None")
            i+=1
            data.insert(str(uuid4()),date,packet[2],packet[3],packet[4],packet[5],packet[6],packet[7],packet[8],packet[9],"TCP")
            data.Commit()
            item_list.append(window2.add_packet(packet,"#E0FFFF"))
            packet_list.append(pkt)


    if pkt.haslayer(UDP):
        if get_ip()== pkt[IP].dst or get_ip()== pkt[IP].src:
            # Classifying packets into UDP Outgoing packets
            packet.append(str(i))
            packet.append(str(time))
            packet.append(str(len(pkt[UDP])))
            packet.append(str(pkt.src))
            packet.append(str(pkt.dst))
            packet.append(str(pkt[IP].src))
            packet.append(str(pkt[IP].dst))
            packet.append(str(pkt.sport))
            packet.append(str(pkt.dport))
            try:
                packet.append(socket.getservbyport(pkt.sport))
            except Exception:
                try:
                    packet.append(socket.getservbyport(pkt.dport))
                except Exception:
                    packet.append("None")
            i+=1
            data.insert(str(uuid4()),date,packet[2],packet[3],packet[4],packet[5],packet[6],packet[7],packet[8],packet[9],"UDP")
            data.Commit()
            item_list.append(window2.add_packet(packet,"#FAFAD2"))
            packet_list.append(pkt)

    # Classifying packets into ICMP
    if pkt.haslayer(ICMP):
        # Classifying packets into UDP Incoming packets
        if get_ip()== pkt[IP].dst or get_ip()== pkt[IP].src:
            packet.append(str(i))
            packet.append(str(time))
            packet.append(str(len(pkt[ICMP])))
            packet.append(str(pkt.src))
            packet.append(str(pkt.dst))
            packet.append(str(pkt[IP].src))
            packet.append(str(pkt[IP].dst))
            packet.append("None")
            packet.append("None")
            packet.append("ICMP")
            i+=1
            data.insert(str(uuid4()),date,packet[2],packet[3],packet[4],packet[5],packet[6],packet[7],packet[8],packet[9],"ICMP")
            data.Commit()
            item_list.append(window2.add_packet(packet,"#FFF0F5"))
            packet_list.append(pkt)




j=1
pcap_item=[]
pcap_list=[]
def read_pcap(pkt):
    global pcap_item
    global pcap_list
    global j
    global is_pcap
    is_pcap="0"
    time=datetime.datetime.now()
    packet=[]

    # Classifying packets into TCP
    if pkt.haslayer(TCP):
        # Classifying packets into TCP Incoming packets
            packet.append(str(j))
            packet.append(str(time))
            packet.append(str(len(pkt[TCP])))
            packet.append(str(pkt.src))
            packet.append(str(pkt.dst))
            packet.append(str(pkt[IP].src))
            packet.append(str(pkt[IP].dst))
            packet.append(str(pkt.sport))
            packet.append(str(pkt.dport))
            try:
                packet.append(socket.getservbyport(pkt.sport))
            except Exception:
                try:
                    packet.append(socket.getservbyport(pkt.dport))
                except Exception:
                    packet.append("None")
            j+=1
            pcap_item.append(window2.add_packet(packet,"#E0FFFF"))
            pcap_list.append(pkt)



    if pkt.haslayer(UDP):
            # classifying packets into UDP Outgoing packets
            packet.append(str(j))
            packet.append(str(time))
            packet.append(str(len(pkt[UDP])))
            packet.append(str(pkt.src))
            packet.append(str(pkt.dst))
            packet.append(str(pkt[IP].src))
            packet.append(str(pkt[IP].dst))
            packet.append(str(pkt.sport))
            packet.append(str(pkt.dport))
            try:
                packet.append(socket.getservbyport(pkt.sport))
            except Exception:
                try:
                    packet.append(socket.getservbyport(pkt.dport))
                except Exception:
                    packet.append("None")
            j+=1
            pcap_item.append(window2.add_packet(packet,"#FAFAD2"))
            pcap_list.append(pkt)


    # Classifying packets into ICMP
    if pkt.haslayer(ICMP):
        # Classifying packets into UDP Incoming packets
        packet.append(str(j))
        packet.append(str(time))
        packet.append(str(len(pkt[ICMP])))
        packet.append(str(pkt.src))
        packet.append(str(pkt.dst))
        packet.append(str(pkt[IP].src))
        packet.append(str(pkt[IP].dst))
        packet.append("None")
        packet.append("None")
        packet.append("ICMP")
        j+=1
        pcap_item.append(window2.add_packet(packet,"#FFF0F5"))
        pcap_list.append(pkt)



def clear(items):
    for item in items:
        window2.deleteItem(item)




 





















if open_window:
    app2.exec_()
























