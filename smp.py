"""
Simple messaging protocol SMP

User token
Command
Message

user should have a token to identify them from the serverside
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
    def __init__(self, token: str = "", cmd: str | None = None, msg: str | None = None):
        self.token = token
        self.cmd = cmd
        self.msg = msg

def encode_message(message: SMP) -> bytes:
    encoded = '\r\n'.join((message.token,  message.cmd, message.msg))
    return (encoded + '\r\n\r\n').encode()

#Need to code error handling in case the client sends a bad packet
def decode_message(encoded: bytes) -> SMP:
    if encoded == b'':
        return -1
    modified = encoded.decode().rstrip('\r\n').split('\r\n')
    if len(modified) == 2:
        return SMP(modified[0], modified[1])
    else:
        return SMP(modified[0], modified[1], modified[2])

def print_packet(envelope: SMP):
    print(f"Token: {envelope.token}")
    print(f"Command: {envelope.cmd}")
    print(f"Message: {envelope.msg}")
