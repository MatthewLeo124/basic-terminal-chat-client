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
import glob
import uuid
import sys
import os

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
        self.token_to_username = {}
        self.log_queue = None
        self.log_thread = None
        self.msg_number = 1 #universal message numbering for dm's
        self.group_chats = {} #{'group_chat_name' : {'msg_count' : 1, 'member' : [], 'joined': []}}

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
                    ret_val = await self.authentication(envelope, client_socket, client_address)

                elif envelope.cmd == "USER":
                    ret_val = self.show_active_users(envelope)

                elif envelope.cmd == "MSG":
                    ret_val = await self.send_message(envelope)
                
                elif envelope.cmd == "MGRP":
                    ret_val = await self.send_message(envelope)

                elif envelope.cmd == "CGRP":
                    ret_val = self.create_group_chat(envelope)

                elif envelope.cmd == "JGRP":
                    ret_val = self.join_group_chat(envelope)

                elif envelope.cmd == "OUT":
                    ret_val = self.logout(envelope)
                    await loop.sock_sendall(client_socket, smp.encode_message(ret_val))
                    client_socket.close()
                    break

                elif envelope.cmd == "VID":
                    pass

                else: #ERR
                    ret_val = smp.SMP(envelope.token, "ERR", "INVALID COMMAND")
    
                await loop.sock_sendall(client_socket, smp.encode_message(ret_val))
            except Exception as e:
                client_socket.close()
                raise e
        return

    async def run(self):
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
        for filename in glob.glob("./*_messageLog.txt"):
            os.remove(filename)

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
                self.log_queue.put({'cmd': "SHUTDOWN"})
                self.log_thread.join()
                break
        return

    async def authentication(self, envelope: smp.SMP, client_socket: socket.socket, client_address: tuple):
        username, password = envelope.msg.split('\n')

        #Case: User is already logged in
        if username in self.active_users and self.active_users[username]['active']:
            envelope.msg = f"TIMEOUT\nSomeone is already logged in with this username!"
            return envelope

        #Case: incorrect username
        if username not in self.credentials:
            envelope.msg = "INVALID\nUSERNAME"
            return envelope

        #Case: Correct username but timed out
        if self.credentials[username]["attempts"] >= self.n_retries:
            timeout = math.floor(time.time()) - self.credentials[username]["timeout"] 
            if timeout <= 10:
                timeout = 10 - timeout #Counts up to 10, hence to count down we take away from 10
                envelope.msg = f"TIMEOUT\nYou are currently timed out, please wait: {str(timeout)}s"
                return envelope
            else:
                self.credentials[username]["attempts"] = 0

        #Case: correct username, not timed out but the password is wrong
        if self.credentials[username]["password"] != password:
            self.credentials[username]["attempts"] += 1
            envelope.msg = "INVALID\nPASSWORD"
            
            #Username locked due to too many attempts
            if self.credentials[username]["attempts"] >= self.n_retries:
                self.credentials[username]["timeout"] = math.floor(time.time())
                timeout = 10 - (math.floor(time.time()) - self.credentials[username]['timeout']) #Counts up to 10, hence to count down we take away from 10
                envelope.msg = f"TIMEOUT\nIncorrect password. You have now been timed out, please try again in :{str(timeout)}s"
                self.log_queue.put({
                    'cmd': 'ERR',
                    'msg': f"Account timeout: The following account has been timed out due to too many failed attempts: {username}"
                })

            return envelope

        ret_val = smp.SMP("", "AUTH", "UDP")

        #Get UDP port
        loop = asyncio.get_event_loop()
        await loop.sock_sendall(client_socket, smp.encode_message(ret_val))
        udp_port = smp.decode_message((await loop.sock_recv(client_socket, 1024)))
        udp_port = str(udp_port.msg)

        #Send Token to user
        user_token = uuid.uuid4()
        user_token = str(user_token)
        ret_val.token = user_token
        ret_val.msg = "SUCCESS"

        #Add user to active users
        self.add_active_user(user_token, username, client_socket, client_address, udp_port)

        return ret_val

    def add_active_user(self, token: str, username: str, client_socket: socket.socket, client_address: tuple, client_udp_port: str):
        if username not in self.active_users:
            user_entry = {
                'username': username,
                'ip': client_address[0],
                'tcp_port': client_address[1],
                'udp_port': client_udp_port,
                'socket': client_socket,
                'login_time': time.time(),
                'token' : token,
                'groups': [],
                'active': True
            }
            self.token_to_username[token] = username
            self.active_users[username] = user_entry
        else:
            self.token_to_username[token] = username
            self.active_users[username]['active'] = True
            self.active_users[username]['socket'] = client_socket
            self.active_users[username]['ip'] = client_address[0]
            self.active_users[username]['tcp_port'] = client_address[1]
            self.active_users[username]['udp_port'] = client_udp_port
            self.active_users[username]['login_time'] = time.time()

        self.log_queue.put({
            'cmd' : 'LOGIN',
            'username': username,
            'ip': client_address[0],
            'udp': client_udp_port,
            'user_number': str(len(self.active_users))
            })
        return

    def show_active_users(self, envelope: smp.SMP):
        ret_val = smp.SMP(envelope.token, envelope.cmd, "")
        for user in self.active_users.values():
            if user['username'] == self.token_to_username[envelope.token]:
                continue
            first = f"{user['username']}, {user['ip']}, {user['udp_port']}, "
            ret_val.msg += first + "active since " + datetime.datetime.fromtimestamp(user['login_time']).strftime('%d/%m/%Y %H:%M:%S') + '\n'
        if ret_val.msg == "":
            ret_val.msg = "no other active users"
        self.log_queue.put({'cmd': 'GEN', 'msg': f"{self.token_to_username[envelope.token]} requested active users. Returning: \n{ret_val.msg}"})
        return ret_val

    def create_group_chat(self, envelope: smp.SMP):
        if not envelope.msg:
            envelope.cmd = "ERR"
            envelope.msg = f"Insufficient arguments provided, please provide the group name and users to add"
            self.log_queue.put({
                'cmd': 'ERR',
                'msg': f"Failed to create group chat for {self.token_to_username[envelope.token]}: Insufficient arguments provided"
            })
            return envelope
        data = envelope.msg.split('\r\r', 1)
        if len(data) == 1:
            envelope.cmd = "ERR"
            envelope.msg = f"Insufficient arguments provided, please provide the users to add"
            self.log_queue.put({
                'cmd': 'ERR',
                'msg': f"Failed to create group chat for {self.token_to_username[envelope.token]}: Insufficient arguments provided"
            })
            return envelope
        group_name, users = data

        #Case: group chat name is not alphanumeric
        if not group_name.isalnum():
            envelope.cmd = "ERR"
            envelope.msg = f"Failed to create group chat: group chat name: '{group_name}' is not valid, please use only [a-z A-Z 0-9]"
            self.log_queue.put({
                'cmd': 'ERR',
                'msg': f"Failed to create group chat [{group_name}] for {self.token_to_username[envelope.token]}: Group chat name is not alphanumeric"
            })
            return envelope

        #Case: group chat already exists
        if group_name in self.group_chats:
            envelope.cmd = "ERR"
            envelope.msg = f"Failed to create group chat: Groupchat: '{group_name}' already exists!"
            self.log_queue.put({
                'cmd': 'ERR',
                'msg': f"Failed to create group chat [{group_name}] for {self.token_to_username[envelope.token]}: Chat already exists"
            })
            return envelope

        users = users.split('\r\r')
        members = []
        for user in users:
            #Case: Can't add someone who isn't active
            if user not in self.active_users or not self.active_users[user]['active']:
                envelope.cmd = "ERR"
                envelope.msg = f"Failed to create group chat: User: {user} is not active"
                self.log_queue.put({
                    'cmd': 'ERR',
                    'msg': f"Failed to create group chat [{group_name}] for {self.token_to_username[envelope.token]}: Tried to add user: {user}, but user is not active"
                })
                return envelope
            
            #Case: User is adding themself to the chatroom.
            if user == self.token_to_username[envelope.token]:
                envelope.cmd = "ERR"
                envelope.msg = f"Failed to create group chat: Cannot add self when creating group chat"
                self.log_queue.put({
                    'cmd': 'ERR',
                    'msg': f"Failed to create group chat [{group_name}] for {self.token_to_username[envelope.token]}: User tried to add self"
                })
                return envelope
        
            #Case: Can't add someone twice
            if user in members:
                envelope.cmd = "ERR"
                envelope.msg = f"Failed to create group chat: Can't add a user to a chatroom twice"
                self.log_queue.put({
                    'cmd': 'ERR',
                    'msg': f"Failed to create group chat [{group_name}] for {self.token_to_username[envelope.token]}: Cannot add duplicate members when creating group chat"
                })
                return envelope
            
            self.active_users[user]['groups'].append(group_name)
            members.append(user)

        members.append(self.token_to_username[envelope.token])
        self.active_users[self.token_to_username[envelope.token]]['groups'].append(group_name)
        self.group_chats[group_name] = {
            'members': members,
            'joined': [],
            'msg_number': 1
        }

        self.log_queue.put({
                'cmd': 'CGRP',
                'group_name': group_name,
                'msg': f"Created group chat: [{group_name}] successfully for {self.token_to_username[envelope.token]}. Users in the room: {members}"
        })
        return smp.SMP(envelope.token, envelope.cmd, f"Group chat created: {group_name}")

    def join_group_chat(self, envelope: smp.SMP):
        if not envelope.msg:
            envelope.cmd = "ERR"
            envelope.msg = f"Insufficient arguments provided, please provide the group name you wish to join"
            self.log_queue.put({
                'cmd': 'ERR',
                'msg': f"Failed to join {self.token_to_username[envelope.token]} to a group chat: Insufficient arguments provided"
            })
            return envelope
        group_name = envelope.msg
        user = self.token_to_username[envelope.token]
        
        #Case: Try to join group chat that does not exist
        if group_name not in self.group_chats:
            envelope.cmd = "ERR"
            envelope.msg = f"Can't join group chat {group_name} since it doesn't exist!"
            self.log_queue.put({
                'cmd': 'ERR',
                'msg': f"Failed to join {user} to group chat [{group_name}]: group chat does not exist"
            })
            return envelope
        
        #Case: User was not added to the group chat when it was created
        if user not in self.group_chats[group_name]['members']:
            envelope.cmd = "ERR"
            envelope.msg = f"You cannot join a group chat you were not added to at creation: {group_name}"
            self.log_queue.put({
                'cmd': 'ERR',
                'msg': f"Failed to join user to groupchat. {user} is not a member of [{group_name}]"
            })
            return envelope

        #Case: User has already joined the group chat
        if user in self.group_chats[group_name]['joined']:
            envelope.cmd = "ERR"
            envelope.msg = f"You have already joined group chat: {group_name}"
            self.log_queue.put({
                'cmd': 'ERR',
                'msg': f"Failed to join user to groupchat. {user} has already joined [{group_name}]"
            })
            return envelope
        
        #Case: Successfully add user to group
        self.group_chats[group_name]['joined'].append(user)
        self.log_queue.put({
            'cmd': 'GEN',
            'msg': f"Successfully joined {user} to groupchat {group_name}. Current users are: {self.group_chats[group_name]['joined']}"
        })
        return smp.SMP(envelope.token, envelope.cmd, f"Successfully joined group chat {group_name}")

    def logout(self, envelope: smp.SMP):
        username = self.token_to_username[envelope.token]
        self.log_queue.put({
            'cmd': 'LOGOUT',
            'username': username
        })
        self.active_users[username]['active'] = False
        del self.token_to_username[envelope.token]
        for group_chat in self.active_users[username]['groups']:
            self.group_chats[group_chat]['joined'].remove(username)

        return smp.SMP(envelope.token, envelope.cmd, "SUCCESS")

    async def send_message(self, envelope: smp.SMP):
        if not envelope.msg:
            envelope.cmd = "ERR"
            envelope.msg = f"Insufficient arguments provided, please provide the user to send to and a message"
            self.log_queue.put({
                'cmd': 'ERR',
                'msg': f"Failed to send message for {self.token_to_username[envelope.token]}: Insufficient arguments provided"
            })
            return envelope

        data = envelope.msg.split('\r\r', 1)
        if len(data) == 1:
            envelope.cmd = "ERR"
            envelope.msg = f"Insufficient arguments provided, please provide a message to send"
            self.log_queue.put({
                'cmd': 'ERR',
                'msg': f"Failed to send message for {self.token_to_username[envelope.token]}: Insufficient arguments provided"
            })
            return envelope

        sender = self.active_users[self.token_to_username[envelope.token]]['username']
        self.log_queue.put({
            'cmd': 'GEN',
            'msg': f"{self.token_to_username[envelope.token]} is trying to send a message"
        })
        
        #Invididual to individual
        if envelope.cmd == "MSG":
            recipient, msg = data

            #Case: User is not active
            if recipient not in self.active_users or not self.active_users[recipient]['active']:
                envelope.cmd = "ERR"
                envelope.msg = f"User: '{recipient}' may not exist or is not active! Message not sent"
                self.log_queue.put({
                    'cmd': 'ERR',
                    'msg': f"Failed to send message for {self.token_to_username[envelope.token]} to {recipient}: User is not in active_users"
                })
                return envelope

            time_sent = datetime.datetime.fromtimestamp(math.floor(time.time())).strftime('%d/%m/%Y %H:%M:%S')
            msg_to_send = '\r\r'.join([sender, time_sent, msg])

            loop = asyncio.get_event_loop()
            await loop.sock_sendall(self.active_users[recipient]['socket'], smp.encode_message(smp.SMP("", envelope.cmd, msg_to_send)))
            self.log_queue.put({
                'cmd': 'MSG',
                'sender': sender,
                'recipient': recipient,
                'time': time_sent,
                'message': msg,
                'msg_number': self.msg_number
            })
            self.msg_number += 1
        
        #Individual to group chat
        else:
            group_chat, msg = data
            
            #Case: group_chat does not exit:
            if group_chat not in self.group_chats:
                envelope.cmd = "ERR"
                envelope.msg = f"Group chat: '{group_chat}' does not exist! Message not sent"
                self.log_queue.put({
                    'cmd': 'ERR',
                    'msg': f"Failed to send message for {self.token_to_username[envelope.token]} to [{group_chat}]: Group chat does not exist"
                })
                return envelope
            
            #Case: User is not a member of the group
            if sender not in self.group_chats[group_chat]['members']:
                envelope.cmd = "ERR"
                envelope.msg = f"Cannot send a message to group chat: '{group_chat}' user is not a member of"
                self.log_queue.put({
                    'cmd': 'ERR',
                    'msg': f"Failed to send message for {self.token_to_username[envelope.token]} to [{group_chat}]: User is not a member"
                })
                return envelope

            #Case: User has not joined the group
            if sender not in self.group_chats[group_chat]['joined']:
                envelope.cmd = "ERR"
                envelope.msg = f"Cannot send a message to group chat: '{group_chat}' user has not joined yet"
                self.log_queue.put({
                    'cmd': 'ERR',
                    'msg': f"Failed to send message for {self.token_to_username[envelope.token]} to [{group_chat}]: User has not joined"
                })
                return envelope

            joined = [*self.group_chats[group_chat]['joined']] #copy list since mutables are passed by reference and not copied
            joined.remove(self.token_to_username[envelope.token])

            #Case: If no one else has joined the group chat other than the sender
            if not len(joined):
                envelope.cmd = "ERR"
                envelope.msg = f"No one else has joined the group chat, failed to broadcast message"
                self.log_queue.put({
                    'cmd': 'ERR',
                    'msg': f"Failed to send message for {self.token_to_username[envelope.token]} to [{group_chat}]: No one else has joined the group chat other than the sender"
                })
                return envelope

            time_sent = datetime.datetime.fromtimestamp(math.floor(time.time())).strftime('%d/%m/%Y %H:%M:%S')
            msg_to_send = '\r\r'.join([sender, group_chat, time_sent, msg])
            msg_envelope = smp.SMP("", envelope.cmd, msg_to_send)

            await self.broadcast_message(joined, msg_envelope)

            self.log_queue.put({
                'cmd': 'MGRP',
                'message': msg,
                'time': time_sent,
                'sender': self.token_to_username[envelope.token],
                'group_name': group_chat,
                'msg_number': self.group_chats[group_chat]['msg_number']
            })
            self.group_chats[group_chat]['msg_number'] += 1

        return smp.SMP(envelope.token, "MSGR", f"Group chat message sent at {time_sent}")

    async def broadcast_message(self, users: list[str], message: smp.SMP):
        loop = asyncio.get_event_loop()
        for user in users:
            await loop.sock_sendall(self.active_users[user]['socket'], smp.encode_message(message))
        return

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

if __name__ == "__main__":
    tcp_port = 15000#int(sys.argv[1])
    attempts = 2#int(sys.argv[2])
    #run the server
    server = Server(tcp_port, attempts)
    asyncio.run(server.run())
