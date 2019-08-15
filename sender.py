from socket import *
import sys
import time
import pickle
import random


# python sender.py receiver_host_ip receiver_port file.txt MWS MSS timeout pdrop seed

# s = socket(AF_INET,SOCK_DGRAM)
# host =sys.argv[1]
# port = 9999
# buf =1024
# addr = (host,port)
#
# file_name=sys.argv[2]
#
# s.sendto(file_name,addr)
#
# f=open(file_name,"rb")
# data = f.read(buf)
# while (data):
#     if(s.sendto(data,addr)):
#         print ("sending ...")
#         data = f.read(buf)
# s.close()
# f.close()


class STP_HEADER:
    def __init__(self, data, seq_num, ack_num, ack=False, syn=False, fin=False):
        self.data = data
        self.seq_num = seq_num
        self.ack_num = ack_num
        self.ack = ack
        self.syn = syn
        self.fin = fin


class Sender:
    def __init__(self, r_host_ip, r_port, file, MWS, MSS, gamma, pdrop, pduplicate, pcorrupt, porder, maxorder,pdelay, maxdelay, seed):
        self.r_host_ip = r_host_ip
        self.r_port = int(r_port)
        self.file = file  # grab file from arg[4]
        self.MSS = int(MSS)
        self.snd_pkt_time = 0
        self.rcv_ack_time = 0
        self.transmit_time = 0
        self.MWS = int(MWS)  # max window size
        self.Max_num_seg = self.MWS / self.MSS
        self.pdrop = pdrop
        self.seed = int(seed)
        self.gamma = int(gamma)
        self.pduplicate = float(pduplicate)
        self.pcorrupt = float(pcorrupt)
        self.porder = porder
        self.maxorder = maxorder
        self.pdelay = pdelay
        self.maxdelay = maxdelay



    # create UDP socket
    socket = socket(AF_INET, SOCK_DGRAM)
    socket.settimeout(0.1)

    def stp_send(self):
        f = open(self.file, "rb")
        data = f.read()
        return data

    def stp_rcv(self):
        try:
            data, addr = self.socket.recvfrom(2048)
        except:
            print("can not rcv")
            return False
        # print("data is, ",data)
        # print("\n3\n")
        # print('1st time senderreceive ack, ', data.ack)
        # print('1st time sender receive ack_num, ', data.ack_num)
        # print('1st time sender receive syn, ', data.syn)
        # print('1st time sender receive seq_num, ', data.seq_num)
        stp_packet = pickle.loads(data)
        self.rcv_ack_time = time.clock() * 1000
        self.transmit_time = self.rcv_ack_time - self.snd_pkt_time
        # print("time diff is: ", self.transmit_time)
        # print("rcv time is: ", self.rcv_ack_time)
        # last_rcv_ack = stp_packet.ack_num
        return stp_packet

    # create SYN
    def make_SYN(self, seq_num, ack_num):
        print("Creating SYN")
        SYN = STP_HEADER('', seq_num, ack_num, ack=False, syn=True, fin=False)
        # print("Sending SYN...")
        return SYN

    # create ACK
    def make_ACK(self, seq_num, ack_num):
        print("Creating ACK")
        ACK = STP_HEADER('', seq_num, ack_num, ack=True, syn=False, fin=False)
        # print("Sending ACK...")
        return ACK

    # create FIN
    def make_FIN(self, seq_num, ack_num):
        print("Creating FIN")
        FIN = STP_HEADER('', seq_num, ack_num, ack=False, syn=False, fin=True)
        return FIN

    def udp_send(self, stp_packet):
        addr = (self.r_host_ip, self.r_port)
        self.socket.sendto(pickle.dumps(stp_packet), addr)
        # print(pickle.dumps(stp_packet))
        if stp_packet.ack:
            print("Sending ACK...")
        if stp_packet.syn:
            print("Sending SYN...")
        else:
            print("Sending DATA...")
        self.snd_pkt_time = time.clock() * 1000

        #print("send time is: ", self.snd_pkt_time)

    def retransmit(self, stp_packet):
        addr = (self.r_host_ip, self.r_port)
        self.socket.sendto(pickle.dumps(stp_packet), addr)
        # print(pickle.dumps(stp_packet))
        if stp_packet.ack:
            print("Sending ACK...")
        if stp_packet.syn:
            print("Sending SYN...")
        else:
            print("Sending DATA...")

    def split_data_pkt(self, data, data_position):
        data_length = len(data)
        # data < MSS, do not need to split data
        if data_position + self.MSS >= data_length:
            # print("no split, data can be at end")
            app_data = data[data_position:data_length]
            # print(app_data)
        else:  # data > MSS, need to be split to small chunks
            # print("need to split, data from data_pos to MSS")
            app_data = data[data_position:data_position + self.MSS]
        return app_data

    # write new line to sender_log.txt
    def write_to_sender_log(self, event, time, packet):
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
        #print("number of bytes",number_of_bytes_data)

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

        f = open("Sender_log.txt", "a+")
        f.write(str_to_file)
        f.close()

    def PLD(self):

        probability = random.random()
        # print(probability)
        # print("pdrop is: ",self.pdrop)
        if probability > float(self.pdrop):
            # no drop, normal send segment
            return "no drop"
        else:
            # drop item
            return "drop it"

    def stp_close(self):
        self.socket.close()


# reset all sender arguments
event = ""
type_of_packet = ""
seq_number = ""
number_of_bytes_data = ""
ack_number = ""

# reset sender_log.txt
f = open("Sender_log.txt", "w")
f.close()

# init seq ack variables.
seq_num = 0
ack_num = 0

# init sender status
state_closed = True
state_syn_sent = False
state_established = False  # send segment
state_end = False

### initiate socket.
# r_host_ip, r_port, file, MWS, MSS, gamma, pdrop, pduplicate, pcorrupt, porder, maxorder,pdelay, maxdelay, seed
r_host_ip = sys.argv[1]
r_port = sys.argv[2]
file = sys.argv[3]
MWS = sys.argv[4]
MSS = sys.argv[5]
gamma = sys.argv[6]
pdrop = sys.argv[7]
pduplicate = sys.argv[8]
pcorrupt = sys.argv[9]
porder = sys.argv[10]
maxorder = sys.argv[11]
pdelay = sys.argv[12]
maxdelay = sys.argv[13]
seed = sys.argv[14]

print("sender initiated...")
sender = Sender(r_host_ip, r_port, file, MWS, MSS, gamma, pdrop, pduplicate, pcorrupt, porder, maxorder,pdelay, maxdelay, seed)
# print("MSS",sender.MSS)
# print("MWS",sender.MWS)
# print("pdrop",sender.pdrop)
# print("seed",sender.seed)
random.seed(sender.seed)
app_data = sender.stp_send()

# initiate data_position, set to 0
data_position = 0
# reset number of segments in window
num_seg_in_window = 0

# reset last_recv_ack
last_rcv_ack = 0

# reset data_buff_dic
data_buff_dic = {}
# reset base_size
base_size = 0
# reset biggest unacked seg:
latest_unacked_seq = 0

# # reset timeout as 1ms
# timeout

# reset start_time:
init_time = time.time()

# reset current_time
current_time = 0


# reset size of file
size_file = len(app_data)
# reset seg transmitted
num_seg_trans = 0
# reset num of seg handled by pld
num_seg_by_pld = 0
# reset seg dropped:
num_seg_drop = 0
# reset seg corrupted:
num_seg_corr = 0
# num seg reordered:
num_seg_reord = 0
# num seg dup:
num_seg_dup = 0
# num seg delay
num_seg_delay = 0
# num retran due to timeout
timeout_retran = 0
# num FAST retran
fast_retran = 0
# num of DUP ack received
num_dup_ack_rcv = 0

def final_log(pre_str_to_file, item_to_write):
    #pre_str_to_file = "Size of the file (in Bytes)"
    tag_to_file = (60 - len(pre_str_to_file)) * " "
    final_str_to_file = pre_str_to_file + tag_to_file + str(item_to_write) + "\n"
    f.write(final_str_to_file)





while True:
    ### CLOSED STATE ###
    if state_closed == True:
        # print("\nSTATE: CLOSED=======================")
        # make sender state open
        # sending connection request, now seq_num=0, ack_num=0
        syn_pkt = sender.make_SYN(seq_num, ack_num)
        # send syn packet
        sender.udp_send(syn_pkt)
        num_seg_trans += 1
        event = "snd"
        current_time = time.time() - init_time
        sender.write_to_sender_log(event, current_time, syn_pkt)
        # print ("1\n")
        state_closed = False
        state_syn_sent = True

    ### START SENDING SYN, WAIT FOR SYNACK BACK
    if state_syn_sent:
        # print("\n SYN SENT=======================")
        # print("seq_num is: ", seq_num)
        # print("ack_num is: ", ack_num)
        # ckeck the synack number
        # print ("2\n")
        synack_pkt = sender.stp_rcv()
        event = "rcv"
        current_time = time.time() - init_time
        sender.write_to_sender_log(event, current_time, synack_pkt)

        # check if packets are SYNACK
        if synack_pkt.ack and synack_pkt.syn:
            ack_num = synack_pkt.seq_num + 1
            # sender's seq_num
            seq_num = seq_num + 1

            # send ACK
            ack_pkt = sender.make_ACK(seq_num, ack_num)
            sender.udp_send(ack_pkt)
            num_seg_trans += 1
            event = "snd"
            current_time = time.time() - init_time
            sender.write_to_sender_log(event, current_time,ack_pkt)
            # second time
            # print("seq_num is: ", seq_num)
            # print("ack_num is: ", ack_num)
            # print("3 way handshake established, ready to transfer data.")
            # connection request complete
            # 3 way handshake established, ready to transfer data.
            state_established = True
            state_syn_sent = False

    ### ESTABLISHED STATE, READY TO TRANSFER DATA
    if state_established:
        # print("\n CONNECTION ESTABLISHED, READY TO TRANSFER DATA")
        # after confirm that it can be sent

        # data_packet = STP_HEADER(app_data, seq_num, ack_num, ack=False,syn=False,fin=False)

        # first check if all data has been transferred, ready to send fin

        ### FIN CONNECTION ###
        # print("data_pos is: ", data_position)
        if data_position == len(app_data):
            if last_rcv_ack == len(app_data) + 1:
                # correctly receive last ack, ready to send fin
                # print("last rcv ack is: ", last_rcv_ack)
                fin_pkt = sender.make_FIN(seq_num, ack_num)
                sender.udp_send(fin_pkt)
                num_seg_trans += 1
                event = "snd"
                current_time = time.time() - init_time
                sender.write_to_sender_log(event, current_time,fin_pkt)
                state_end = True
                state_established = False
                # print("fin_pkt.ack_num is: ", fin_pkt.ack_num)
                # print("fin_pkt.seq_num is: ", fin_pkt.seq_num)
                # print("FIN sent, wait for first ACK")
            else:
                # all data send, ready to receive, do not send any data forward
                ack_pkt = sender.stp_rcv()
                last_rcv_ack = ack_pkt.ack_num
                event = "rcv"
                current_time = time.time() - init_time
                sender.write_to_sender_log(event, current_time,ack_pkt)
                ack_num += len(ack_pkt.data)
                num_seg_in_window -= 1
        else:
            # not end, transmit data
            # print("when package data, data_pos is: ",data_position)
            # print("when package, seq_num is: ",seq_num)
            app_data_split = sender.split_data_pkt(app_data, data_position)
            # print("app_data_split is: ", app_data_split)
            #print("len(app_data): ",len(app_data_split))
            data_packet = STP_HEADER(app_data_split, seq_num, ack_num, ack=False, syn=False, fin=False)
            # print(seq_num)
            # print(ack_num)
            # print("data_packet.app_data",len(data_packet.data))
            # store data to data_buff, to avoid data drop.
            data_buff_dic[seq_num] = app_data_split
            if num_seg_in_window < sender.Max_num_seg:
                # print("keep sending")
                drop_or_not = sender.PLD()
                num_seg_by_pld += 1
                # print(drop_or_not)
                if drop_or_not == "drop it":
                    event = "drop"
                    current_time = time.time() - init_time
                    sender.write_to_sender_log(event, current_time,data_packet)
                    # print("data_packet.seq",data_packet.seq_num)
                    # print("when drop, data_pos is: ",data_position)
                    num_seg_trans += 1
                    seq_num += len(app_data_split)
                    num_seg_in_window += 1
                    num_seg_drop += 1
                    data_position += len(app_data_split)
                    #start_time = time.clock() * 1000
                    #print("start drop time is:",start_time)
                else:
                    # no drop
                    event = "snd"
                    # keep doing send operation
                    # print("send data")
                    # print("when send data, data pos is: ",data_position)
                    # print("sent seq_num is: ",data_packet.seq_num)

                    # print("sent data is: ",data_packet.data)
                    sender.udp_send(data_packet)
                    num_seg_trans += 1
                    if data_packet.seq_num > latest_unacked_seq:
                        latest_unacked_seq = data_packet.seq_num
                    #print("biggeste_unacked seq", latest_unacked_seq)
                    #print("sent ack is: ",data_packet.ack_num)

                    current_time = time.time() - init_time
                    sender.write_to_sender_log(event, current_time,data_packet)
                    #print("there")

                    data_position += len(app_data_split)
                    seq_num += len(app_data_split)
                    num_seg_in_window += 1

            else:
                # window is full, sender must recv ack from receiver
                # print("window is full, sender begin to recv")
                # print("num_in_window is: ", num_seg_in_window)
                # print("basesize is: ",base_size)
                # data_position += len(app_data_split)

                if sender.Max_num_seg > 1:
                    if base_size == sender.Max_num_seg - 1:
                        # all dup ack has been rcved, ready to retran
                        # base_size == sender.Max_num_seg - 1 and
                        # pld decide if drop the retransmission
                        drop_or_not = sender.PLD()
                        num_seg_by_pld += 1
                        # print(drop_or_not)
                        if drop_or_not == "drop it":
                            event = "drop"
                            current_time = time.time() - init_time
                            sender.write_to_sender_log(event, current_time, data_packet)
                            # print("data_packet.seq",data_packet.seq_num)
                            # print("when drop, data_pos is: ",data_position)
                            num_seg_trans += 1
                            seq_num += len(app_data_split)
                            num_seg_in_window += 1
                            num_seg_drop += 1
                        else:
                            # do not drop, retransmit
                            #print("ready to RXT")
                            event = "snd/RXT"
                            # print("fast retransmission")
                            fast_retran += 1
                            #print("seq_num is before-----------------------:",seq_num)
                            seq_num = last_rcv_ack
                            #print("last",last_rcv_ack)
                            data_position = seq_num - 1
                            #print("seq_num is after:-----------------------", seq_num)
                            #print(data_buff_dic)
                            app_data_split = data_buff_dic[seq_num]
                            data_packet = STP_HEADER(app_data_split, seq_num, 1, ack=False, syn=False, fin=False)
                            # print("when send RXT, data pos is:",data_position)
                            sender.udp_send(data_packet)
                            num_seg_trans += 1
                            current_time = time.time() - init_time
                            sender.write_to_sender_log(event, current_time,data_packet)
                            x = base_size + 1
                            data_position += (len(app_data_split) * x)

                            seq_num += (len(app_data_split) * x)
                            # reset base_size
                            num_seg_in_window -= base_size
                            base_size = 0
                    else:
                        # keep rcv dup ack
                        ack_pkt = sender.stp_rcv()
                        if ack_pkt:
                            # duplicate ACK received, num_seg_in_window remains the same
                            if last_rcv_ack == ack_pkt.ack_num:
                                event = "rcv/DA"
                                num_dup_ack_rcv += 1
                                current_time = time.time() - init_time
                                sender.write_to_sender_log(event, current_time,ack_pkt)
                                ack_num += len(ack_pkt.data)
                                last_rcv_ack = ack_pkt.ack_num
                                # print("num_seg_in_window", num_seg_in_window)
                                data_position -= len(app_data_split)
                                seq_num -= len(app_data_split)
                                base_size += 1
                            # print("after rcv/DA, base_size is: ",base_size)
                            # now window is full, sender have to resend dropped packets.
                        else:
                            # normal ack received
                            event = "rcv"
                            current_time = time.time() - init_time
                            sender.write_to_sender_log(event, current_time,ack_pkt)
                            ack_num += len(ack_pkt.data)
                            num_seg_in_window -= 1
                            # print("when normal rcv, last_ack_num is: ",last_rcv_ack)
                            # print("when normal rcv, ack_pkt.ack_num is: ",ack_pkt.ack_num)
                            last_rcv_ack = ack_pkt.ack_num
                            #print("when rcv, last_ack_num is: ",last_rcv_ack)
                            # print("nomral rcv succeed, ready to normal send")

                else:
                    # window size = 1, normal stop-and-wait protocol
                    #current_time = time.clock() * 1000

                    # print("stop and wait protocol, ready to rcv")
                    # print("before rcv:",time.time())
                    ack_pkt = sender.stp_rcv()
                    # print("after rcv",time.time())
                    if ack_pkt == False:
                        # timeout, need to retransmit

                        # pld decide if drop the pkt
                        drop_or_not = sender.PLD()
                        num_seg_by_pld += 1
                        # print(drop_or_not)
                        if drop_or_not == "drop it":
                            event = "drop"
                            current_time = time.time() - init_time
                            sender.write_to_sender_log(event, current_time, data_packet)
                            # print("data_packet.seq",data_packet.seq_num)
                            # print("when drop, data_pos is: ",data_position)
                            num_seg_trans += 1
                            seq_num += len(app_data_split)
                            num_seg_in_window += 1
                            num_seg_drop += 1
                            #data_position += len(app_data_split)
                        else:
                            # do not drop, retransmit
                            timeout_retran += 1
                            # print("stop and wait retransmit")
                            event = "snd/RXT"
                            #seq_num -= len(app_data_split)
                            # found out no ack back, means dropped, so begin to retransmit
                            # reset data pos
                            seq_num = last_rcv_ack
                            data_position = seq_num - 1
                            # print("when stop and wait retrans, data_pos is: ",data_position)
                            # print("when stop and wait retrans, seq_num is: ", seq_num)
                            app_data_split = data_buff_dic[seq_num]
                            data_packet = STP_HEADER(app_data_split, seq_num, ack_num, ack=False, syn=False, fin=False)
                            # print("retransmit data seq is: ",data_packet.seq_num)
                            # print("when retrans, data_pos is: ",data_position)
                            # print("when retransmit, last_ack is: ",last_rcv_ack)
                            sender.udp_send(data_packet)
                            num_seg_trans += 1
                            current_time = time.time() - init_time
                            sender.write_to_sender_log(event, current_time,data_packet)
                            data_position += len(app_data_split)
                            seq_num += len(app_data_split)
                            #num_seg_in_window -= 1
                            #sys.exit()

                    else:
                        # rcv succeed
                        # print("rcv succeed, stop and wait protocol rcv")
                        # print("current_time",current_time)

                        # print("when rcv, seq_num is: ", seq_num)
                        #last_rcv_ack = seq_num
                        #print("when rcv, ack_rcv is:", last_rcv_ack)

                        if last_rcv_ack == ack_pkt.ack_num:
                            # duplicate ACK received, num_seg_in_window remains the same

                            event = "rcv/DA"
                            num_dup_ack_rcv += 1
                            current_time = time.time() - init_time
                            sender.write_to_sender_log(event, current_time,ack_pkt)
                            ack_num += len(ack_pkt.data)
                            last_rcv_ack = ack_pkt.ack_num
                            # print("num_seg_in_window", num_seg_in_window)
                            data_position -= len(app_data_split)
                            seq_num -= len(app_data_split)
                            base_size += 1


                            # now window is full, sender have to resend dropped packets.

                        else:
                            # normal ack received
                            print("stop and wait normal rcv")
                            event = "rcv"
                            current_time = time.time() - init_time
                            sender.write_to_sender_log(event, current_time,ack_pkt)
                            ack_num += len(ack_pkt.data)
                            num_seg_in_window -= 1
                            # print("when normal rcv, last_ack_num is: ",last_rcv_ack)
                            # print("when normal rcv, ack_pkt.ack_num is: ",ack_pkt.ack_num)
                            last_rcv_ack = ack_pkt.ack_num
                            #print("when rcv, last_ack_num is: ",last_rcv_ack)
                            # print("nomral rcv succeed, ready to normal send")


    ### END OF CONNECTION, WAIT FOR ACK ###
    if state_end == True:
        print("\n STATE: END OF CONNECTION===============")
        ack_pkt = sender.stp_rcv()
        event = "rcv"
        current_time = time.time() - init_time
        sender.write_to_sender_log(event, current_time,ack_pkt)
        # print("First ACK received, ready to receive second Fin")
        # print("ack_pkt.ack_num is: ", ack_pkt.ack_num)
        # print("ack_pkt.seq_num is: ", ack_pkt.seq_num)
        # if ack is received, wait for FIN
        # print("ack_pkt.ack, ", ack_pkt)
        if ack_pkt.ack:
            # receive FIN from receiver, if received, send last ACK
            fin_pkt = sender.stp_rcv()
            event = "rcv"
            current_time = time.time() - init_time
            sender.write_to_sender_log(event, current_time,fin_pkt)
            #print("Second Fin received")
            #print("ACK IS: ", fin_pkt.ack_num)
            #print("SEQ IS: ", fin_pkt.seq_num)
            #print("FIN IS: ", fin_pkt.fin)
            if fin_pkt.fin:
                # print("2")
                ack_num += 1
                ack_pkt = sender.make_ACK(seq_num, ack_num)
                sender.udp_send(ack_pkt)
                num_seg_trans += 1
                event = "snd"
                current_time = time.time() - init_time
                sender.write_to_sender_log(event, current_time,ack_pkt)
                print("Last ACK sent, close the stp")
                ### LAST ACK SENT, CONNECTION CLOSED
                sender.stp_close()
                # start record final result to log file
                f = open("Sender_log.txt", "a+")
                #f.write(str_to_file)
                f.write("==================================================================\n")
                init_tag = 60
                pre_str_to_file = "Size of the file (in Bytes)"
                final_log(pre_str_to_file,size_file)
                pre_str_to_file = "Segments transmitted (including drop & RXT)"
                final_log(pre_str_to_file,num_seg_trans)
                pre_str_to_file = "Number of segments handled by PLD"
                final_log(pre_str_to_file,num_seg_by_pld)
                pre_str_to_file = "Number of segments dropped"
                final_log(pre_str_to_file,num_seg_drop)
                pre_str_to_file = "Number of segments Corrupted"
                final_log(pre_str_to_file,num_seg_corr)
                pre_str_to_file = "Number of segments Re-ordered"
                final_log(pre_str_to_file,num_seg_reord)
                pre_str_to_file = "Number of segments Duplicated"
                final_log(pre_str_to_file,num_seg_dup)
                pre_str_to_file = "Number of segments Delayed"
                final_log(pre_str_to_file,num_seg_delay)
                pre_str_to_file = "Number of Retransmissions due to TIMEOUT"
                final_log(pre_str_to_file,timeout_retran)
                pre_str_to_file = "FAST RETRANSMISSION"
                final_log(pre_str_to_file,fast_retran)
                pre_str_to_file = "Number of DUP ACKS received"
                final_log(pre_str_to_file,num_dup_ack_rcv)
                f.write("==================================================================\n")
                f.close()

                # # reset size of file
                # size_file = len(app_data)
                # # reset seg transmitted
                # num_seg_trans = 0
                # # reset seg dropped:
                # num_seg_drop = 0
                # # reset seg corrupted:
                # num_seg_corr = 0
                # # num seg reordered:
                # num_seg_reord = 0
                # # num seg dup:
                # num_seg_dup = 0
                # # num seg delay
                # num_seg_delay = 0
                # # num retran due to timeout
                # timeout_retran = 0
                # # num FAST retran
                # fast_retran = 0
                # # num of DUP ack received
                # num_dup_ack_rcv = 0



                break
            else:
                # print("3")
                break
