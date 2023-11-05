#python3 client.py 127.0.0.1 15000 12000
#Handle client data
import threading
import socket
import time
import sys
import smp

def run():
    clientSocket, clientUDPPort = setup_client()
    print("Please login to the server. (Case sensitive)")
    username, token = client_authentication(clientSocket, clientUDPPort)
    print("Successfully logged in")

    tcp_listener_flag, tcp_listener_thread = create_listener_threads(clientSocket)

    input_message = """Enter one of the following commands: [/msgto, /activeuser, /creategroup, /joingroup, /groupmsg, /p2pvideo, /logout]\n>"""
    while True:
        message = input(input_message)
        if len(message) == 0:
            continue
        command_envelope = smp.SMP(token, "", "")

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
                command_envelope.msg = "\r\r".join(message[1].split(" ", 1))

        #/msgto username message
        elif cmd == "/msgto":
            command_envelope.cmd = "MSG"
            if data:
                command_envelope.msg = '\r\r'.join(message[1].split(" ", 1))

        #TODO: Implement function
        elif cmd == "/p2pvideo":
            print("This feature has not been implemented yet.")

        elif cmd == "/logout":
            command_envelope.cmd = "OUT"

        elif cmd == "/q":
            break

        else:
            print("\nUnknown command has been input.\n")
            continue

        clientSocket.sendall(smp.encode_message(command_envelope))

        if cmd == "/logout":
            break

        time.sleep(0.01)

    #close the socket
    tcp_listener_flag[0] = True
    tcp_listener_thread.join()
    #udp_listener.join()
    clientSocket.close()
    print(f"See you later {username}!")

def setup_client():
    if len(sys.argv) != 4:
        print("\n===== Error usage: python3 client.py SERVER_IP SERVER_PORT CLIENT_UDP_PORT ======\n")
        exit(0)

    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serverHost = sys.argv[1]
    serverPort = int(sys.argv[2])
    clientUDPPort = int(sys.argv[3])
    serverAddress = (serverHost, serverPort)

    clientSocket.connect(serverAddress)
    return (clientSocket, clientUDPPort)

def client_authentication(clientSocket, clientUDPPort):
    username = None
    while True:
        if not username:
            username = input("Username: ")
        password = input("Password: ")
        login_envelope = smp.SMP("", "AUTH", f"{username}\n{password}")
        
        clientSocket.sendall(smp.encode_message(login_envelope))
        response = smp.decode_message(clientSocket.recv(1024))
        if response == -1:
            print("Server suddenly closed the connection, shutting down")
            clientSocket.close()
            exit(0)
        
        outcome = response.msg.split('\n')
        if outcome[0] == "UDP":
            login_envelope.msg = str(clientUDPPort)
            clientSocket.sendall(smp.encode_message(login_envelope))
            response = smp.decode_message(clientSocket.recv(1024))
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

def create_listener_threads(clientSocket):
    #Create listener thread
    clientSocket.settimeout(1)
    tcp_listener_flag = [False]
    tcp_listener_thread = threading.Thread(target=tcp_listener, args=(clientSocket, tcp_listener_flag, ))
    tcp_listener_thread.start()

    #Setup UDP server
    #clientUDPSocket = socket(AF_INET, SOCK_DGRAM)
    #udpAddress = (CLIENT_IP, clientUDPPort)
    #clientUDPSocket.bind(udpAddress)
    #udp_listener = threading.Thread(target=udp_listener, args=(clientUDPSocket, ))

    return tcp_listener_flag, tcp_listener_thread

#killed_flag is bad coding, shouldn't use a mutable structure as a flag but should write as a class.
def tcp_listener(clientSocket: socket.socket, killed_flag: list):
    while True:
        if killed_flag[0]:
            break

        # receive response from the server
        # 1024 is a suggested packet size, you can specify it as 2048 or others
        receivedMessage = None
        try:
            data = clientSocket.recv(1024)
            if data == b'':
                print("\nLost connection to server, type /q to exit the client\n")
                break
            receivedMessage = smp.decode_message(data)
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
            print(f"\n{time_sent}, {sender} -> {group_chat}: {message}\n", flush=True, end="")

        #Message was malformed and server didn't read it.
        elif receivedMessage.cmd == "MAL":
            pass

        else:
            print(f"\n{receivedMessage.msg}\n", flush=True)

def udp_listener():
    #payload, client_address = sock.recvfrom(1)
	#print("Echoing data back to " + str(client_address))
	#sent = sock.sendto(payload, client_address)
    pass

if __name__ == "__main__":
    run()
