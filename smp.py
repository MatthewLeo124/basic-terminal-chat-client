"""
Simple messaging protocol SMP

HEADER

FROM <IP:PORT>\r\n #If its from the server, it will be the server TCP port, else its a user UDP port
TO <IP:PORT>\r\n #Its the users UDP Port
CMD\r\n

BODY

MSG\r\n\r\n
"""

"""
CMD's available
auth -> AUTH
active user -> ACTV
msg to -> MSG
create group -> CGRP
join group -> JGRP
group msg -> MSG
p2p video -> VID
logout -> OUT
What is your UDP port -> UDP
error -> ERR
"""

class SMP:
    def __init__(self, sender_ip: str | None = None, sender_port: str | None = None, receiver_ip: str | None = None, receiver_port: str | None = None, cmd: str | None = None, msg: str | None = None):
        self.sender_ip = sender_ip
        self.sender_port = sender_port
        self.receiver_ip = receiver_ip
        self.receiver_port = receiver_port
        self.cmd = cmd
        self.msg = msg

def encode_message(message: SMP) -> bytes:
    h_sender = f"{message.sender_ip}:{message.sender_port}"
    h_receiver = f"{message.receiver_ip}:{message.receiver_port}"
    h_cmd = f"{message.cmd}"
    h_msg = f"{message.msg}"
    encoded = '\r\n'.join((h_sender, h_receiver, h_cmd, h_msg))
    return (encoded + '\r\n\r\n').encode()

#Need to code error handling in case the client sends a bad packet
def decode_message(encoded: bytes) -> SMP:
    if encoded == b'':
        return -1
    modified = encoded.decode().rstrip('\r\n').split('\r\n')
    s_ip, s_port = modified[0].split(':')
    r_ip, r_port = modified[1].split(':')
    return SMP(s_ip, s_port, r_ip, r_port, modified[2], modified[3])

def print_packet(envelope: SMP):
    print(f"Sender IP: {envelope.sender_ip}")
    print(f"Sender Port: {envelope.sender_port}")
    print(f"Receiver IP: {envelope.receiver_ip}")
    print(f"Receiver Port: {envelope.receiver_port}")
    print(f"Command: {envelope.cmd}")
    print(f"Message: {envelope.msg}")
