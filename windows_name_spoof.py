#! /usr/bin/env python3

# script to generate a fake windows netbios name and trick machines to dicover it.

import random
import string
import socket
from struct import pack
from time import sleep

nbns_port=137
browser_port=138

workgroup="WORKGROUP"

broadcast="192.168.1.255" #to be calculated later

#maximum length of names in ascii
MAX_NAME_LENGTH=15

#16 bit endian swapper
ByteSwap = lambda x: (x >> 8)|(x << 8)&(0xffff)

#32 bit byte swap
ByteSwap32 = lambda x: (x >> 24)&0xff | \
(x << 8)&(0xff0000) | \
(x >> 8)&0xff00 | \
(x << 24)&0xff000000


#microsofts stupid bullshit way of encoding chars
def wierd_encoder(name, isWorkgroup = False, isTypeServer = False):
   
    encoded=[]
    
    #make sure names are not too long
    if len(name) > MAX_NAME_LENGTH:
        name = name[:MAX_NAME_LENGTH]
    
    for c in name:
        c = ord(c)
        left = (c >> 4) & 0xff
        right = (c & 0x000f)
        
        left = left + ord('A')
        right = right + ord('A')      
        
        encoded.append(left)
        encoded.append(right)
        
        #encoded.append((left << 8) | right)
    
    #so you think its done eh??
    #because microsofts encoding method is so retarded, the name must be padded to 32 bytes
    # using the pattern 0x43, 0x41... and 0x4141 on the final 2 bytes!
    
    encoded = bytes(encoded)
    
    pad_1 = 0x43
    pad_2 = 0x41
    
    pad_length = (32 - len(encoded))    
    
    if pad_length > 0:
        padding = [pad_1, pad_2] * int(pad_length / 2 )

        if isWorkgroup == True:
            #for some reason work groups end in ABN (0x41,0x42,0x4e) instead of ACA (0x41,0x43, 0x41)
            padding[-1] = 0x4e
            padding[-2] = 0x42
        else:
            if isTypeServer == False:
                #type server is padded with ACA
                #type workstatsion is padded with AAA
                padding[-2] = pad_2
        
        encoded = encoded + bytes(padding)
    
    #then the encoded name must start with a 0x20 and end with a 0x00
    
    encoded = b'\x20' + encoded + b'\x00'
    
    # WOW microsoft, all that to make it harder to find out hostnames.
    # wouldn't it have been easier to give the name in ascii and add a few flags to the SMB packet to tell us if it is a workstation or server
    # no wonder microsoft software sucks so bad
    
    return encoded

#make a random string
def randomString(length = MAX_NAME_LENGTH):
    random.seed()
    return "".join(random.choice(string.ascii_uppercase + string.digits) for _ in range(length))

#send a nbns regeistering the hostname
def SendNbnsRegistration(hostname,host_addr): 
    #header
    random.seed()
    trans_id = random.randint(0, 0xffff)
    
    flags = 0x2910
    questions = 0x0001
    answers = 0x0000
    authorities = 0x0000
    additional = 0x0001

    #query
    #start name with a 0x20 and end with 0x00

    query_type = 0x0020 #NB
    query_class= 0x0001 #IN

    #additional
    pre_additional=0xc00c

    #name
    #type, class
    TTL = 0x000493e0 #3 days 11h 20m    
    data_len = 0x0006 #to be worked out
    name_flags = 0x0000

    #del hostname
    #print(hostname)
    encoded_hostname = wierd_encoder(hostname)

    #print(''.join('0x'+format(x, '02x')+',' for x in hostname))

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    addr=(broadcast,nbns_port)

    #craft the packet (as workstation)
    message = pack("!HHHHHH"+ str(len(encoded_hostname)) +"sHHHHHIHHI", trans_id, flags, questions, answers, authorities, additional, \
    encoded_hostname, query_type, query_class, pre_additional, query_type, query_class, \
    TTL, data_len, name_flags, host_addr)
    
    encoded_hostname = wierd_encoder(hostname, isTypeServer = True)
    
    #send the socket
    s.sendto(message, addr)
    
    
    #craft and send as a server type
    message = pack("!HHHHHH"+ str(len(encoded_hostname)) +"sHHHHHIHHI", trans_id, flags, questions, answers, authorities, additional, \
    encoded_hostname, query_type, query_class, pre_additional, query_type, query_class, \
    TTL, data_len, name_flags, host_addr)
    
    #send the socket
    s.sendto(message, addr)

    s.close()


#send a browser announcement
def sendBrowserAnnouncement(hostname,host_addr):

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    addr=(broadcast,browser_port)

    #craft the packet
    #structure:
        #NetBIOS datagram
        #SMB header
        #SMB mailslot
        #the actual browse
    
    #generate each in reverse as the section before includes sizes of the next  

    #craft the packet
    
    #step 1: craft the Broswer proto
    browser_cmd = 0x01 #(1byte) #host announcement, 0x01, local master announcent= 0x0f
    browser_update_count = 0x02 #(1 byte)
    browser_update_period = 0x20120a00 #(11 min, need to figure out how this is determined)

    #pad the hostname with 0s
    max_browser_name_bytes = 16   
    browser_hostname = bytes(hostname, "ascii")
    
    if len(browser_hostname) > max_browser_name_bytes:
        browser_hostname = browser_hostname[0:max_browser_name_bytes -1]
        
    pad_size = max_browser_name_bytes - len(browser_hostname)
    padding = bytes([0] * pad_size)
    
    browser_hostname = browser_hostname + padding
    
    win_ver = 0x0601 #6.1 - windows 7
    
    server_type = ByteSwap32(0x00019003) #workstation, server, NT
    
    smb_version = 0x0f01
    
    signature = ByteSwap(0xaa55) #to be determined how this is calculated
    
    comment = b"YAY!!!!! I'm tricking windaz PCs.\x00"
    
    browser = pack("!BBI16sHIHH" + str(len(comment)) + "s", \
    browser_cmd, browser_update_count, browser_update_period, browser_hostname, \
    win_ver, server_type, smb_version, signature, comment)
    
    # notice how most of the same data repeats in different in formats in each section of the payload?
    # its a microsoft thing, the more lines of code the more likely there will be an error
    
    #step 2: craft the Mailslot stuff
    mailslot_name = b'\\MAILSLOT\\BROWSE\x00'
       
    #flags and crap   
    mailslot_pre = bytes([0x01, 0x00, 0x01, 0x00, 0x02, 0x00])
    mailslot_size= len(mailslot_name) + len(browser) #also byte_count in smb trans
        
    #swap endianness of mailslot_size (make it little endian)
    mailslot_size = ByteSwap(mailslot_size)
    
    mailslot = pack("!6sH" + str(len(mailslot_name)) +"s", mailslot_pre, mailslot_size, mailslot_name)
    
    
    #step 3: SMB
    
    #header is 32 bytes
    smb_component = 0xff534d42
    smb_trans = 0x25
    smb_header_flags = bytes([0] * 27) # (32 - 4 - 1)
    
    #trans part
    word_count = len(mailslot_name)
    #total paramater count = 0 (2bytes)
    total_data_count = ByteSwap(len(browser))
    smb_trans_options = bytes([0]*18)
    #data_count = total_data_count

    #data_offset = 86 #not sure how they get this, could be a constant
    #little endian, so 0x5600
    #setup_count = 0x03
    #reserved = 0x00
      
    SMB = pack("!IB" + str(len(smb_header_flags)) + "sBHH" + str(len(smb_trans_options)) \
    + "sHHBB", smb_component, smb_trans, smb_header_flags, \
    word_count, 0x0000, total_data_count, smb_trans_options, \
    total_data_count, 0x5600, 0x03, 0)
    
    
    
    #step 4: datagram crap
    initial_bytes = 0x1102 #flags
    random.seed()
    datagram_id = random.randint(0, 0xffff)
        
    encoded_name = wierd_encoder(hostname, isTypeServer = True)
    wkgp = wierd_encoder(workgroup, True)
        
    dgram_len = len(encoded_name) + len(wkgp) + len(SMB)
        
    netbios_dgram_message = pack("!HHIHHH" + str(len(encoded_name)) + "s" + str(len(wkgp)) + "s", \
    initial_bytes, datagram_id, host_addr, browser_port, dgram_len, 0x0000, \
    encoded_name, wkgp)
    


    # send the socket
    message = netbios_dgram_message + SMB + mailslot + browser
    #message = netbios_dgram_message + mailslot
    s.sendto(message, addr)

    s.close()

def main():
    
    #print(wierd_encoder(workgroup, True))
    #print(wierd_encoder("USER-PC"))
    
    # randomize the hostname and ip.
    random.seed()
    hostname = randomString()
    host_addr = random.randint(0, 0xffffffff)
    
    print(hostname + "=" + \
    str(socket.inet_ntoa(pack("!I", host_addr))))
    
    while True:
        # lets trick windows!
        SendNbnsRegistration(hostname,host_addr) 
        sendBrowserAnnouncement(hostname,host_addr)
        
        sleep(120) # delay for 2 mins and send it again.
        

main()

