#python3 client.py 127.0.0.1 15000 12000
#Handle client data
import threading
import socket
import time
import sys
import os

#Simple message protocol
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

def run():
    if len(sys.argv) != 4:
        print("\n===== Error usage: python3 client.py SERVER_IP SERVER_PORT CLIENT_UDP_PORT ======\n")
        exit(0)

    serverHost = sys.argv[1]
    serverPort = int(sys.argv[2])
    clientUDPPort = int(sys.argv[3])
    serverAddress = (serverHost, serverPort)

    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    clientSocket.settimeout(1)

    clientUDPSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    clientUDPSocket.settimeout(1)

    udpAddress = ('127.0.0.1', clientUDPPort)
    clientUDPSocket.bind(udpAddress)

    clientSocket.connect(serverAddress)
    print("Please login to the server. (Case sensitive)")
    username, token = client_authentication(clientSocket, clientUDPPort)
    print("Successfully logged in")

    #Create listener thread
    kill_flag = [False]
    tcp_queue = []
    tcp_listener_thread = threading.Thread(target=tcp_listener, args=(clientSocket, kill_flag, tcp_queue, ))
    tcp_listener_thread.start()

    #Setup UDP server
    udp_queue = []
    udp_listener_thread = threading.Thread(target=udp_listener, args=(clientUDPSocket, kill_flag, udp_queue, ))
    udp_listener_thread.start()

    input_message = """Enter one of the following commands: [/msgto, /activeuser, /creategroup, /joingroup, /groupmsg, /p2pvideo, /logout]\n>"""
    while True:
        message = input(input_message)
        if len(message) == 0:
            continue
        command_envelope = SMP(token, "", "")

        message = message.split(" ", 1)
        cmd = message[0]
        data = message[1] if len(message) > 1 else None

        #/activeuser
        if cmd == "/activeuser":
            command_envelope.cmd = "USER"

        #/creategroup groupname username1 username2 ...
        elif cmd == "/creategroup":
            command_envelope.cmd = "CGRP"
            if data:
                command_envelope.msg = '\r\r'.join(data.split())

        #/joingroup groupname
        elif cmd == "/joingroup":
            command_envelope.cmd = "JGRP"
            if data:
                command_envelope.msg = message[1].strip()
        
        #/groupmsg groupname message
        elif cmd == "/groupmsg":
            command_envelope.cmd = "MGRP"
            if data:
                command_envelope.msg = "\r\r".join(data.split(" ", 1))

        #/msgto username message
        elif cmd == "/msgto":
            command_envelope.cmd = "MSG"
            if data:
                command_envelope.msg = '\r\r'.join(data.split(" ", 1))

        #TODO: May have to have this idling in a background thread
        #/p2pvideo <person> <filename>
        elif cmd == "/p2pvideo":
            command_envelope.cmd = "VID"
            if data:
                data = data.split(" ", 1)
                command_envelope.msg = data[0]

            clientSocket.sendall(encode_message(command_envelope))

            #Timeout after 1 second
            timeout = 0
            while not len(tcp_queue) and timeout < 1000:
                time.sleep(0.001)
                timeout += 1
            #We timed out, 
            if timeout >= 1000:
                print("Timed out receiving userdata from server")
                continue
            user_data = tcp_queue.pop()
            if user_data == -1:
                continue
            
            if len(data) != 2:
                print("\nNot enough arguments provided! Cannot perform action\n")
                continue
            
            #Send the video to the other person
            #1 = error, 0 = finished
            filename = data[1].split()[0]
            error = 0
            chunk = 0

            #Check if the file exists, print error if not
            if not os.path.isfile(filename):
                print("\nCannot send file: File does not exist! Please provide a valid file to send\n")
                continue

            #Handshake
            handshake = error.to_bytes(1, 'big') + chunk.to_bytes(4, 'big') + f"{username}\r\r{filename}".encode()
            clientUDPSocket.sendto(handshake, user_data)

            #Wait for ACK
            timeout = 0
            while not len(udp_queue) and timeout < 10000: #Timeout after 1 second
                time.sleep(0.001)
                timeout += 1
            if timeout >= 10000:
                print("Timed out receiving ACK from target user")
                continue
            
            received = udp_queue.pop()
            err = received[0]
            chunk = received[1]
            
            if err:
                print("An error has occured from the receiver, failed to send file to target")
                continue

            if chunk != 1:
                print("Invalid response returned, failed to send file to target")
                continue

            chunk += 1 #Increment chunk to 2 as the server has accepted the connection
            timeout = 0
            with open(filename, "r+b") as f:
                try:
                    while data := f.read(1019):
                        data = error.to_bytes(1, 'big') + chunk.to_bytes(4, 'big') + data
                        clientUDPSocket.sendto(data, user_data)
                        while not len(udp_queue) and timeout < 10000:
                            time.sleep(0.001)
                            timeout += 1
                        if timeout >= 10000:
                            raise Exception("Timed out wait for ACK from target user")
                        timeout = 0
                        ack_packet = udp_queue.pop()
                        err = ack_packet[0]
                        if err:
                            print("An error has occured from the receiver, failed to send file to target")
                            continue
                        chunk += 1
                    error = 0
                    data = error.to_bytes(1, 'big') + chunk.to_bytes(4, 'big')
                    clientUDPSocket.sendto(data, user_data)
                    print(f"\n{filename} has been uploaded successfully\n")
                except Exception as e:
                    print(e)
                    error = 1
                    data = error.to_bytes(1, 'big') + chunk.to_bytes(4, 'big')
                    clientUDPSocket.sendto(data, user_data)
            continue

        elif cmd == "/logout":
            command_envelope.cmd = "OUT"

        elif cmd == "/q":
            break

        else:
            print("\nUnknown command has been input.\n")
            continue

        clientSocket.sendall(encode_message(command_envelope))

        if cmd == "/logout":
            break

        time.sleep(0.01)

    #close the socket
    kill_flag[0] = True
    tcp_listener_thread.join()
    udp_listener_thread.join()
    clientSocket.close()
    clientUDPSocket.close()
    print(f"See you later {username}!")

def client_authentication(clientSocket, clientUDPPort):
    username = None
    while True:
        if not username:
            username = input("Username: ")
        password = input("Password: ")
        login_envelope = SMP("", "AUTH", f"{username}\n{password}")
        
        clientSocket.sendall(encode_message(login_envelope))
        response = decode_message(clientSocket.recv(1024))
        if response == -1:
            print("Server suddenly closed the connection, shutting down")
            clientSocket.close()
            exit(0)
        
        outcome = response.msg.split('\n')
        if outcome[0] == "UDP":
            login_envelope.msg = str(clientUDPPort)
            clientSocket.sendall(encode_message(login_envelope))
            response = decode_message(clientSocket.recv(1024))
            token = response.token
            break
        elif outcome[0] == "INVALID":
            print(f"Invalid {outcome[1]}, please try again")
            if outcome[1] == "USERNAME":
                username = None
        elif outcome[0] == "TIMEOUT":
            print(outcome[1])
            exit(0)
        else:
            print("Unknown error\nServer message: ", outcome[0])
    return (username, token)

#killed_flag is bad coding, shouldn't use a mutable structure as a flag but should write as a class.
def tcp_listener(clientSocket: socket.socket, killed_flag: list, tcp_queue: list):
    while True:
        if killed_flag[0]:
            break

        receivedMessage = None
        try:
            data = clientSocket.recv(1024)
            if data == b'':
                print("\nLost connection to server, type /q to exit the client\n")
                break
            receivedMessage = decode_message(data)
        except socket.timeout:
            continue
        except OSError as e:
            print(e, flush=True)
            break

        if receivedMessage.cmd == "OUT":
            break

        elif receivedMessage.cmd == "MSG":
            sender, time_sent, message = receivedMessage.msg.split('\r\r') #handle message
            print(f"\n{time_sent}, {sender}: {message}\n", flush=True, end="")
        
        elif receivedMessage.cmd == "MGRP":
            sender, group_chat, time_sent, message = receivedMessage.msg.split('\r\r') #handle message
            print(f"\n{time_sent}, {group_chat}, {sender}: {message}\n", flush=True, end="")

        elif receivedMessage.cmd == "VID":
            data = receivedMessage.msg.split('\r\r')
            if data[0] == "ERR":
                print(f"\n{data[1]}\n", flush=True)
                data = -1
            else:
                data = (data[0], int(data[1]))
            tcp_queue.append(data)

        else:
            print(f"\n{receivedMessage.msg}\n", flush=True)

def udp_listener(sock: socket.socket, kill_flag: list, udp_queue: list):
    while True:
        if kill_flag[0]:
            break
        try:
            initiation, client_address = sock.recvfrom(1024)
            error = int.from_bytes(initiation[:1], 'big')
            current_chunk = int.from_bytes(initiation[1:5], 'big')
            #Initiate new transaction
            #If the sequence number is < 0, malformed packet, discard
            if current_chunk < 0:
                continue

            #Case: if current_chunk > 0: then we are in the middle of sending a file to someone
            if current_chunk > 0:
                udp_queue.append((error, current_chunk))
                continue

            #Case: If current_chunk == 0, then someone wants to send data to us
            current_chunk += 1 #Increment sequence
            ret_val = 0 #Append error byte
            ret_val = ret_val.to_bytes(1, 'big') + current_chunk.to_bytes(4, 'big')
            sock.sendto(ret_val, client_address)

            filename = initiation[5:].decode()
            sender, f_name = filename.split("\r\r", 1)
            filename = f"{sender}_{f_name}"
            with open(filename, "wb") as f:
                timeout = 0
                curr_err = 0
                while True:
                    try:
                        data, client_address_curr = sock.recvfrom(1024)

                        #If the data did not come from the one who initiated the transmission, discard the packet
                        if client_address_curr != client_address:
                            continue

                        #Reset timeout if something is heard from server
                        timeout = 0

                        #Something happened at sender, kill transaction
                        error = int.from_bytes(data[:1], 'big')
                        if error > 0: 
                            break

                        #No more data to receive
                        if not data[5:]:
                            print(f"\nReceived {f_name} from {sender}\n")
                            break
    
                        to_write = data[5:]
                        f.write(to_write)
                        f.flush()
                        current_chunk += 1

                        ack = curr_err.to_bytes(1, 'big') + current_chunk.to_bytes(4, 'big')
                        sock.sendto(ack, client_address)

                    #If nothing heard from sender in 2 seconds, kill the connection
                    except socket.timeout:
                        timeout += 1
                        if timeout > 10:
                            error = 1
                            data = error.to_bytes(1, 'big') + current_chunk.to_bytes(4, 'big')
                            sock.sendto(data, client_address)
                            break
                        continue
                    except OSError as e:
                        print(e, flush=True)
                        break
        except socket.timeout:
            continue
        except OSError as e:
            print(e, flush=True)
            break

if __name__ == "__main__":
    run()
