#python3 client.py 127.0.0.1 15000 12000
#Handle client data
import threading
import socket
import time
import sys
import smp

def run():
    #Server would be running on the same host as Client
    if len(sys.argv) != 4:
        print("\n===== Error usage: python3 client.py SERVER_IP SERVER_PORT CLIENT_UDP_PORT ======\n")
        exit(0)

    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serverHost = sys.argv[1]
    serverPort = int(sys.argv[2])
    clientUDPPort = int(sys.argv[3])
    CLIENT_IP = "127.0.0.1"
    serverAddress = (serverHost, serverPort)

    clientSocket.connect(serverAddress)

    #Log in to server
    print("Please login to the server. (Case sensitive)")
    username = None
    while True:
        if not username:
            username = input("Username: ")
        password = input("Password: ")
        login_envelope = smp.SMP(CLIENT_IP, clientUDPPort, serverHost, serverPort, "AUTH", f"{username}\n{password}")
        
        clientSocket.sendall(smp.encode_message(login_envelope))
        response = smp.decode_message(clientSocket.recv(1024))
        if response == -1:
            print("Server suddenly closed the connection, shutting down")
            clientSocket.close()
            exit(0)
        
        outcome = response.msg.split('\n')
        if outcome[0] == "SUCCESS":
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

    print("Successfully logged in")

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

    input_message = """Enter one of the following commands: [/msgto, /activeuser, /creategroup, /joingroup, /groupmsg, /p2pvideo, /logout]\n>"""

    while True:
        message = input(input_message)
        if len(message) == 0:
            continue
        command_envelope = smp.SMP(
            CLIENT_IP,
            clientUDPPort,
            serverHost,
            serverPort,
            "",
            ""
        )

        message = message.split(" ", 1)
        cmd = message[0]
        if cmd == "/msgto":
            command_envelope.cmd = "MSG"
            recipient, sender_msg = message[1].split(" ", 1)
            if sender_msg.isspace():
                continue
            command_envelope.msg = '\r\r'.join(["ONE", username, recipient, str(0), sender_msg]) #f"ONE\r\r{username}\r\r{recipient}\r\r0\r\r{sender_msg}" #from, to, msg

        elif cmd == "/activeuser":
            command_envelope.cmd = "USER"
            command_envelope.msg = username

        elif cmd == "/creategroup":
            if len(message) == 1:
                print("ERR: Please specify the group chat name and the users you wish to put in there.")
            data = message[1].split()
            if len(data) == 1:
                print("ERR: Please specify both the group chat name and the users you wish to put into the group chat.")
            command_envelope.cmd = "CGRP"
            command_envelope.msg = '\r\r'.join(message[1].split())

        elif cmd == "/joingroup":
            if len(message) == 1:
                print("ERR: Please specify the group chat name that you wish to join")
            command_envelope.cmd = "JGRP"
            command_envelope.msg = f'{username}\r\r{message[1].strip()}'

        elif cmd == "/groupmsg":
            if len(message) == 1:
                print("ERR: Please specify the group chat name and your message.")
            data = message[1].split(" ", 1)
            if len(data) == 1:
                print("ERR: Please specify both the group chat name and the message you wish to send.")
            command_envelope.cmd = "MSG"
            command_envelope.msg = f"MANY\r\r{data[0]}\r\r{data[1]}"

        elif cmd == "/p2pvideo":
            print("This feature has not been implemented yet.")

        elif cmd == "/logout":
            command_envelope.cmd = "OUT"
            command_envelope.msg = username

        else:
            print("\nUnknown command has been input.\n")
            continue

        clientSocket.sendall(smp.encode_message(command_envelope))

        if command_envelope.cmd == "OUT" or cmd == "/q":
            break

        time.sleep(0.01)

    # close the socket
    tcp_listener_flag[0] = True
    tcp_listener_thread.join()
    #udp_listener.join()
    clientSocket.close()
    print(f"See you later {username}!")

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
            receivedMessage = smp.decode_message(data)
        except socket.timeout:
            continue
        except OSError as e:
            print(e, flush=True)
            break

        if receivedMessage.cmd == "OUT":
            break

        elif receivedMessage.cmd == "MSG":
            _, sender, _, time_sent, message = receivedMessage.msg.split('\r\r') #handle message
            options = """Enter one of the following commands: [/msgto, /activeuser, /creategroup, /joingroup, /groupmsg, /p2pvideo, /logout]\n>"""
            print(f"\n\n{time_sent}, {sender}: {message}\n\n{options}", flush=True, end="")

        else:
            print(f"\n\n{receivedMessage.msg}\n", flush=True)

def udp_listener():
    #payload, client_address = sock.recvfrom(1)
	#print("Echoing data back to " + str(client_address))
	#sent = sock.sendto(payload, client_address)
    pass

if __name__ == "__main__":
    run()
