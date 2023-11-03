#To run
#python3 server.py 15000 5
#Standard Libs
import threading
import datetime
import asyncio
import socket
import queue
import time
import math
import sys

#My libs
import logger
import smp

"""
    CMD's available
    auth -> AUTH
    active user -> USER
    msg to -> MSG
    create group -> CGRP
    join group -> JGRP
    group msg -> MSG
    logout -> OUT
    error -> ERR
"""

SERVER_IP = "127.0.0.1"

class Server:
    def __init__(self, port: int, retries: int):
        self.n_retries = retries
        self.address = (SERVER_IP, port)
        self.socket = None
        self.credentials = {} #{'username' : {'password' : "password", 'attempts' : 0, timeout: INT (time), session: INT (time)}}
        self.active_users = {} #{'username': {username dictionaries}}
        self.log_queue = None
        self.log_thread = None
        self.msg_number = 1 #universal message numbering for dm's
        self.group_chats = {} #{'group_chat_name' : {'msg_count' : 1, 'users' : []}}

    #address = (ip, port)
    async def handle_client(self, client_socket: socket.socket, client_address: tuple):
        loop = asyncio.get_event_loop()
        ret_val = None

        while True:
            try:
                envelope = smp.decode_message((await loop.sock_recv(client_socket, 1024)))
                if envelope == -1:
                    self.log_queue.put({'cmd': "GEN", 'msg': f"client: {client_address} has suddenly closed connection"})
                    client_socket.close()
                    break
                
                if envelope.cmd == "AUTH":
                    ret_val = self.authentication(envelope, client_socket, client_address)

                elif envelope.cmd == "USER":
                    ret_val = self.show_active_users(envelope)

                elif envelope.cmd == "MSG":
                    ret_val = await self.send_message(envelope)

                elif envelope.cmd == "CGRP":
                    ret_val = self.create_envelope_from_server(envelope.sender_ip, envelope.sender_port, "ERR", "This feature has not been implemented yet!")

                elif envelope.cmd == "JGRP":
                    ret_val = self.create_envelope_from_server(envelope.sender_ip, envelope.sender_port, "ERR", "This feature has not been implemented yet!")

                elif envelope.cmd == "OUT":
                    ret_val = self.logout(envelope)
                    await loop.sock_sendall(client_socket, smp.encode_message(ret_val))
                    client_socket.close()
                    break

                else: #ERR
                    ret_val = self.create_envelope_from_server(envelope.sender_ip, envelope.sender_port, "ERR", "INVALID COMMAND")
    
                await loop.sock_sendall(client_socket, smp.encode_message(ret_val))
            except Exception as e:
                client_socket.close()
                raise e
        return

    async def run(self) -> None:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind(self.address)
        self.socket.listen(8)
        self.socket.setblocking(False)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.log_queue = queue.Queue(maxsize=0)
        self.log_thread = threading.Thread(target=logger.run_logging, args=(self.log_queue, ))
        self.log_thread.start()

        #Wipe the files
        with open("messagelog.txt", "w") as _:
            pass
        with open("userlog.txt", "w") as _:
            pass

        self.load_credentials()
        loop = asyncio.get_event_loop()

        while True:
            try:
                client, address = await loop.sock_accept(self.socket)
                client.setblocking(False)
                loop.create_task(self.handle_client(client, address))
            except Exception as e:
                print(e)
                self.socket.close()
                #Close logging thread
                self.log_queue.put({'cmd': "SHUTDOWN"})
                self.log_thread.join()
                break
        return

    #Login functions
    def authentication(self, envelope: smp.SMP, client_socket: socket.socket, client_address: tuple):
        username, password = envelope.msg.split('\n')

        #Case: User is already logged in
        if username in self.active_users:
            return self.create_envelope_from_server(envelope.sender_ip, envelope.sender_port, "AUTH", f"TIMEOUT\nSomeone is already logged in with this username!")

        #Case: incorrect username
        if username not in self.credentials:
            return self.create_envelope_from_server(envelope.sender_ip, envelope.sender_port, "AUTH", "INVALID\nUSERNAME")

        #Case: Correct username but timed out
        if self.credentials[username]["attempts"] >= self.n_retries:
            timeout = math.floor(time.time()) - self.credentials[username]["timeout"] 
            if timeout <= 10:
                timeout = 10 - timeout #Counts up to 10, hence to count down we take away from 10
                return self.create_envelope_from_server(envelope.sender_ip, envelope.sender_port, "AUTH", f"TIMEOUT\nYou are currently timed out, please wait: {str(timeout)}s")
            else:
                self.credentials[username]["attempts"] = 0

        #Case: correct username, not timed out but the password is wrong
        if self.credentials[username]["password"] != password:
            self.credentials[username]["attempts"] += 1
            
            #Username locked due to too many attempts
            if self.credentials[username]["attempts"] >= self.n_retries:
                self.credentials[username]["timeout"] = math.floor(time.time())
                timeout = 10 - (math.floor(time.time()) - self.credentials[username]['timeout']) #Counts up to 10, hence to count down we take away from 10
                return self.create_envelope_from_server(envelope.sender_ip, envelope.sender_port, "AUTH", f"TIMEOUT\nIncorrect password. You have now been timed out, please try again in :{str(timeout)}s")

            return self.create_envelope_from_server(envelope.sender_ip, envelope.sender_port, "AUTH", "INVALID\nPASSWORD")
        
        #Case: Correct username and password
        ret_val = self.create_envelope_from_server(envelope.sender_ip, envelope.sender_port, "AUTH", "SUCCESS")

        #Add user to active users
        self.add_active_user(envelope, username, client_socket, client_address)
        return ret_val

    def add_active_user(self, envelope: smp.SMP, username: str, client_socket: socket.socket, client_address: tuple):
        user_entry = {
            'username': username,
            'ip': client_address[0],
            'tcp_port': client_address[1],
            'udp_port': envelope.sender_port,
            'socket': client_socket,
            'login_time': time.time()
        }
        self.active_users[username] = user_entry
        self.log_queue.put({
            'cmd' : 'LOGIN',
            'username': username,
            'ip': client_address[0],
            'udp': envelope.sender_port,
            'user_number': str(len(self.active_users))
            })
        return

    #Active users function
    def show_active_users(self, envelope: smp.SMP):
        ret_val = self.create_envelope_from_server(envelope.sender_ip, envelope.sender_port, envelope.cmd, "")
        for user in self.active_users.values():
            if user['username'] == envelope.msg:
                continue
            first = f"{user['username']}, {user['ip']}, {user['udp_port']}, "
            ret_val.msg += first + "active since " + datetime.datetime.fromtimestamp(user['login_time']).strftime('%d/%m/%Y %H:%M:%S') + '\n'
        if ret_val.msg == "":
            ret_val.msg = "no other active users"
        self.log_queue.put({'cmd': 'GEN', 'msg': f"{envelope.msg} requested active users. Return message: \n{ret_val.msg}"})
        return ret_val

    #Logout functions
    def logout(self, envelope: smp.SMP):
        self.log_queue.put({
            'cmd': 'LOGOUT',
            'username': envelope.msg
        })
        del self.active_users[envelope.msg]
        return self.create_envelope_from_server(envelope.sender_ip, envelope.sender_port, envelope.cmd, "SUCCESS")

    async def send_message(self, envelope: smp.SMP): #return value is the successful sending of the message
        #command_envelope.msg = f"ONE/many\r\r{username}\r\r{recipient}\r\r0\r\r{sender_msg}" #from, to, msg
        #1-1 messaging
        cmd, sender, recipient, _, msg = envelope.msg.split('\r\r', 4)
        if cmd == "ONE": #individual messaging
            if recipient not in self.active_users:
                return self.create_envelope_from_server(envelope.sender_ip, envelope.sender_port, "MSGR", f"User: '{recipient}' is not active! Message not sent")
            time_sent = datetime.datetime.fromtimestamp(math.floor(time.time())).strftime('%d/%m/%Y %H:%M:%S')
            msg_to_send = '\r\r'.join([cmd, sender, recipient, time_sent, msg])
            to_send = smp.SMP(envelope.sender_ip, envelope.sender_port, self.active_users[recipient]['ip'], self.active_users[recipient]['udp_port'], envelope.cmd, msg_to_send)
            loop = asyncio.get_event_loop()
            await loop.sock_sendall(self.active_users[recipient]['socket'], smp.encode_message(to_send))
        else: #Group message
            pass
        #from, to, message, time
        self.log_queue.put({'cmd': 'MSG', 'sender': sender, 'recipient': recipient, 'time': time_sent, 'message': msg, 'msg_number': self.msg_number})
        self.msg_number += 1
        return self.create_envelope_from_server(envelope.sender_ip, envelope.sender_port, "MSGR", f"message sent at {time_sent}")

    #Helper functions
    def load_credentials(self):
        with open("credentials.txt", "r") as f:
            for line in f:
                username, password = line.rstrip().split()
                self.credentials[username] = {
                        'password': password,
                        'attempts': 0,
                        'timeout': -1
                }
        return

    def create_envelope_from_server(self, sender_ip: str, sender_port: str, cmd: str | None=None, message: str | None=None):
        ret_val = smp.SMP()
        ret_val.sender_ip = SERVER_IP
        ret_val.sender_port = str(self.address[1])
        ret_val.receiver_ip = sender_ip
        ret_val.receiver_port = sender_port 
        ret_val.cmd = cmd
        ret_val.msg = message
        return ret_val

if __name__ == "__main__":
    tcp_port = 15000#int(sys.argv[1])
    attempts = 2#int(sys.argv[2])
    #run the server
    server = Server(tcp_port, attempts)
    asyncio.run(server.run())
