#!/usr/bin/env python
import os

# from socket import *
# import sys
# import select
#
# host="0.0.0.0"
# port = 9999
# s = socket(AF_INET,SOCK_DGRAM)
# s.bind((host,port))
#
# addr = (host,port)
# buf=1024
#
# data,addr = s.recvfrom(buf)
# #print("data strip",data.strip())
# #file_path = "/Desktop/" + data.strip()
# filename = "new_file.txt"
# print("Received File:","new_file.txt")
# f = open(filename,'wb')
#
# data,addr = s.recvfrom(buf)
# try:
#     while(data):
#         f.write(data)
#         s.settimeout(2)
#         data,addr = s.recvfrom(buf)
# except timeout:
#     f.close()
#     s.close()
#     print ("File Downloaded")


import pickle
import sys
import time
from socket import *


class STP_HEADER:
    def __init__(self, data, seq_num, ack_num, ack=False, syn=False, fin=False):
        self.data = data
        self.seq_num = seq_num
        self.ack_num = ack_num
        self.ack = ack
        self.syn = syn
        self.fin = fin


class Receiver:
    # initialise receiver data
    def __init__(self, port, file):
        self.port = int(port)
        self.file = file

    # create udp socket
    socket = socket(AF_INET, SOCK_DGRAM)

    # receive packet from sender, return pkt + client address

    def stp_rcv(self):
        # print("waiting for file . . .")
        data, client_addr = self.socket.recvfrom(2048)
        # print("data is ",data)
        stp_packet = pickle.loads(data)
        return stp_packet, client_addr

    def append_payload(self, data):
        # print("Appending packet payload = {}".format(data))
        f = open("r_test.pdf", "a+")
        # print("type of data",type(data))
        f.write(data)
        f.close()

    # create SYNACK
    def make_SYNACK(self, seq_num, ack_num):
        print("Creating SYNACK")
        SYNACK = STP_HEADER('', seq_num, ack_num, ack=True, syn=True, fin=False)
        return SYNACK

    # create ACK
    def make_ACK(self, seq_num, ack_num):
        print("Creating ACK")
        ACK = STP_HEADER('', seq_num, ack_num, ack=True, syn=False, fin=False)
        return ACK

    # create FIN
    def make_FIN(self, seq_num, ack_num):
        print("Creating FIN")
        FIN = STP_HEADER('', seq_num, ack_num, ack=False, syn=False, fin=True)
        return FIN

    # send segment over UDP
    def udp_send(self, packet, addr):
        self.socket.sendto(pickle.dumps(packet), addr)

    # write new line to Receiver_log.txt
    def write_to_receiver_log(self, event, time, packet):
        str_to_file = ""
        space_tab = "        "
        space_dec = 0
        # check type_of_packet is S or SA or D
        if packet.syn and packet.ack:
            type_of_packet = "SA"
            space_dec = 1
        elif packet.syn:
            type_of_packet = "S"
        elif packet.ack:
            type_of_packet = "A"
        elif packet.fin:
            type_of_packet = "F"
        else:
            type_of_packet = "D"

        seq_number = packet.seq_num
        ack_number = packet.ack_num
        number_of_bytes_data = len(packet.data)

        str_to_file += space_tab
        str_to_file += str(event)
        space_dec = len(str(event)) - 3
        if space_dec > 0:
            str_to_file += space_tab[:(-1 * space_dec)]
        else:
            str_to_file += space_tab

        # format output time
        time = "%.2f" % time
        str_to_file += space_tab
        str_to_file += str(time)
        space_dec = len(str(time)) - 3
        if space_dec > 0:
            str_to_file += space_tab[:(-1 * space_dec)]
        else:
            str_to_file += space_tab

        str_to_file += space_tab
        str_to_file += str(type_of_packet)
        space_dec = len(str(type_of_packet)) - 1
        if space_dec > 0:
            str_to_file += space_tab[:(-1 * space_dec)]
        else:
            str_to_file += space_tab
        str_to_file += str(seq_number)
        space_dec = len(str(seq_number)) - 1
        if space_dec > 0:
            str_to_file += space_tab[:(-1 * space_dec)]
        else:
            str_to_file += space_tab
        str_to_file += str(number_of_bytes_data)
        space_dec = len(str(number_of_bytes_data)) - 1
        if space_dec > 0:
            str_to_file += space_tab[:(-1 * space_dec)]
        else:
            str_to_file += space_tab
        str_to_file += str(ack_number)
        str_to_file = str_to_file + "\n"

        f = open("Receiver_log.txt", "a+")
        f.write(str_to_file)
        f.close()

    def stp_close(self):
        print("Connection closed")
        self.socket.close()


# init seq ack variables.
seq_num = 0
ack_num = 0

# init receiver status
state_listen = True
state_syn_rcv = False
state_synack_sent = False
state_established = False  # send segment
state_end = False

# grab args, create socket and bind
port, file = sys.argv[1:]
receiver = Receiver(port, file)
receiver.socket.bind(('', receiver.port))

# reset final file
f = open("r_test.pdf", "wb")
f.close()

# reset all receiver argumrnts
event = ""
type_of_packet = ""
seq_number = ""
number_of_bytes_data = ""
ack_number = ""

# reset receiver_log.txt
f = open("Receiver_log.txt", "w")
f.close()

# reset start_time:
init_time = time.time()
init_count = 0

# reset current_time
current_time = 0


# initiate data_position
data_position = 0

# reset last_snd_ack:
last_snd_ack = 0

# reset buff_size to store segments before window is full.
buff_size = 0
buff_data = ""

# reset amount data received
data_bytes_rcv = 0
# reset segments_received
seg_rcv = 0
# reset data_seg received
data_seg_rcv = 0
# reset seg with error
seg_error = 0
# reset seg_dup_recv
seg_dup_rcv = 0
# reset dup_ack_sent
dup_ack_sent = 0


def final_log(pre_str_to_file, item_to_write):
    #pre_str_to_file = "Size of the file (in Bytes)"
    tag_to_file = (60 - len(pre_str_to_file)) * " "
    final_str_to_file = pre_str_to_file + tag_to_file + str(item_to_write) + "\n"
    f.write(final_str_to_file)


while True:
    # print("start of loop")
    if state_listen:
        print ("\nSTATE: LISTEN=======================")
        syn_pkt, client_addr = receiver.stp_rcv()

        if init_count >= 1:
            init_time = init_time
        else:
            init_time = time.time()
        init_count += 1
        event = "rcv"
        current_time = time.time() - init_time
        receiver.write_to_receiver_log(event,current_time,syn_pkt)
        #data_seg_rcv += 1
        seg_rcv += 1
        # print("client_addr, ",client_addr)
        # print('1st time receive ack, ',syn_pkt.ack)
        # print('1st time receive ack_num, ',syn_pkt.ack_num)
        # print('1st time receive syn, ',syn_pkt.syn)
        # print('1st time receive seq_num, ',syn_pkt.seq_num)




        # expect to receive the 1st message from sender, so ack_num = 1
        ack_num += 1
        # creating SYNACK
        if syn_pkt.syn == True:
            # now seq_num=0, ack_num=1
            synack_pkt = receiver.make_SYNACK(seq_num,ack_num)
            receiver.udp_send(synack_pkt,client_addr)
            event = "snd"
            current_time = time.time() - init_time
            receiver.write_to_receiver_log(event, current_time,synack_pkt)
            # increment seq for SYNACK
            seq_num += 1
            state_synack_sent = True
            state_listen = False

    ### SYNACK SENT
    # wait for sender ACK back
    if state_synack_sent == True:
        print ("\nSTATE: SYNACK==================")
        ack_pkt,client_addr = receiver.stp_rcv()
        event = "rcv"
        current_time = time.time() - init_time
        receiver.write_to_receiver_log(event,current_time,ack_pkt)
        seg_rcv += 1
        if ack_pkt.ack == True:
            # ack is True, means the ack_num sent from receiver is valid.
            state_established = True
            state_synack_sent = False

    ### 3-way-handshake established
    if state_established == True:
        print ("\n STATE: CONNECTION ESTABLISHED")
        while True:
            packet, client_addr = receiver.stp_rcv()
            event = "rcv"
            current_time = time.time() - init_time
            receiver.write_to_receiver_log(event, current_time,packet)
            if len(packet.data) > 0:
                data_seg_rcv += 1
            #data_seg_rcv += 1
            seg_rcv += 1
            #ack_num += len(packet.data)
            # print("seq_num is: ",seq_num)
            # print("packet.seq_num is: ",packet.seq_num)
            # # check if seq_num is correct.
            # print("ack_num is: ",ack_num)

            # receive fin, file transfer done
            if packet.fin:
                print("received first FIN")
                # print("fin_pkt.ack_num is: ", packet.ack_num)
                # print("fin_pkt.seq_num is: ", packet.seq_num)

                state_end = True
                state_established = False
                break

            if packet.seq_num == ack_num:
                #seq_num good, ACK back
                # print("good ack-------------")
                if buff_size > 0:
                    # print("ack is: ",ack_num)
                    #print("buffer size is:", buff_size)
                    ack_num += (len(packet.data) * (buff_size + 1))
                    #print("buff data is: ",buff_data)
                    buff_size = 0

                    ack_pkt = receiver.make_ACK(seq_num, ack_num)
                    # print("I am going to send ack number is: ", ack_pkt.ack_num)
                    receiver.udp_send(ack_pkt, client_addr);
                    event = "snd"
                    current_time = time.time() - init_time
                    receiver.write_to_receiver_log(event, current_time ,ack_pkt)
                    last_snd_ack = ack_num

                    data = packet.data
                    # print("data is:",data)
                    receiver.append_payload(data)
                    data_bytes_rcv += len(data)
                    receiver.append_payload(buff_data)
                    data_bytes_rcv += len(buff_data)
                    # after append buffer, reset buffer data to ""
                    buff_data = ""
                    seq_num = 1
                else:
                    # print("no buff size---")
                    ack_num += len(packet.data)

                    ack_pkt = receiver.make_ACK(seq_num, ack_num)
                    # print("I am going to send ack number is: ", ack_pkt.ack_num)
                    receiver.udp_send(ack_pkt, client_addr);
                    event = "snd"
                    current_time = time.time() - init_time
                    receiver.write_to_receiver_log(event, current_time,ack_pkt)
                    last_snd_ack = ack_num

                    data = packet.data
                    # print("good////////////////////////////////")
                    # print("pkt_seq_num",packet.seq_num)
                    # print("no buff size data is:",packet.data)
                    receiver.append_payload(data)
                    data_bytes_rcv += len(data)
                    seq_num = 1
            else:
                # print("seq_number wrong")
                # some packets dropped.
                # do not add ack_num, just send it to sender
                if ack_num == last_snd_ack:
                    ack_pkt = receiver.make_ACK(seq_num, ack_num)
                    receiver.udp_send(ack_pkt, client_addr);
                    event = "snd/DA"
                    current_time = time.time() - init_time
                    receiver.write_to_receiver_log(event, current_time,ack_pkt)
                    dup_ack_sent += 1
                    buff_size += 1
                    buff_data += packet.data
                    # print("data is: ",packet.data)
                    # print("packet.seq",packet.seq_num)
                    # print("buff_size is: /////////////////////////////////////",buff_size)
                    # received but not acked data has been stored into data buffer.
                else:
                    ack_pkt = receiver.make_ACK(seq_num, ack_num)
                    receiver.udp_send(ack_pkt, client_addr);
                    event = "snd"
                    current_time = time.time() - init_time
                    receiver.write_to_receiver_log(event, current_time,ack_pkt)






    ### CLOSE CONNECTION ###
    if state_end:
        print("\n STATE: END OF CONNECTION================")
        ack_num += 1
        ack_pkt = receiver.make_ACK(seq_num,ack_num)
        # print("ACK IS: ",ack_pkt.ack_num)
        # print("SEQ IS: ", ack_pkt.seq_num)
        receiver.udp_send(ack_pkt,client_addr)
        event = "snd"
        current_time = time.time() - init_time
        receiver.write_to_receiver_log(event, current_time,ack_pkt)
        print("FIrst ACK sent, ready to send second Fin")
        # after sending ACK, send FIN of receiver
        fin_pkt = receiver.make_FIN(ack_num,seq_num)
        print("ACK IS: ",fin_pkt.ack_num)
        print("SEQ IS: ", fin_pkt.seq_num)
        print("FIN is: ",fin_pkt.fin)
        receiver.udp_send(fin_pkt,client_addr)
        event = "snd"
        current_time = time.time() - init_time
        receiver.write_to_receiver_log(event, current_time,fin_pkt)
        print("Second Fin sent, ready to receive second ACK")

        # wait for last ACK fom server
        ack_pkt, client_addr= receiver.stp_rcv()
        event = "rcv"
        current_time = time.time() - init_time
        receiver.write_to_receiver_log(event,current_time,ack_pkt)
        seg_rcv += 1
        print("Last ACK recieved, close the stp")
        if ack_pkt.ack:
            receiver.stp_close()
            # Print final file
            # print("\n### FINAL FILE.TXT CONTENT ###")
            # f = open("r_test.pdf", "rb")
            # print(f.read())
            print("File downloaded")
            print("start record final log")
            f = open("Receiver_log.txt", "a+")
            # f.write(str_to_file)
            f.write("==================================================================\n")
            init_tag = 60
            pre_str_to_file = "Amount of data received (bytes)"
            final_log(pre_str_to_file, data_bytes_rcv)
            pre_str_to_file = "Total Segments received"
            final_log(pre_str_to_file,seg_rcv)
            pre_str_to_file = "Data Segments received"
            final_log(pre_str_to_file, data_seg_rcv)
            pre_str_to_file = "Data Segments with Bit Errors"
            final_log(pre_str_to_file, seg_error)
            pre_str_to_file = "Duplicate data Segments received"
            final_log(pre_str_to_file,seg_dup_rcv)
            pre_str_to_file = "Duplicate ACKs sent"
            final_log(pre_str_to_file,dup_ack_sent)
            f.write("==================================================================\n")
            f.close()

            break
        else:
            # print("wrong")
            break
# # reset amount data received
# data_bytes_rcv = 0
# # reset segments_received
# seg_rcv = 0
# reset data_seg received
# data_seg_rcv = 0
# # reset seg with error
# seg_error = 0
# # reset seg_dup_recv
# seg_dup_rcv = 0
# reset dup_ack_sent
# dup_ack_sent = 0

