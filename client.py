#To run
#python3 client.py 127.0.0.1 15000 12000
#Handle client data
from socket import *
import sys
import smp

#Server would be running on the same host as Client
if len(sys.argv) != 4:
    print("\n===== Error usage, python3 TCPClient3.py SERVER_IP SERVER_PORT ======\n")
    exit(0)

CLIENT_IP = "127.0.0.1"

serverHost = sys.argv[1]
serverPort = int(sys.argv[2])
serverAddress = (serverHost, serverPort)
clientUDPPort = int(sys.argv[3])
# define a socket for the client side, it would be used to communicate with another client
clientUDPSocket = socket(AF_INET, SOCK_DGRAM)
# define a socket for the client side, it would be used to communicate with the server
clientSocket = socket(AF_INET, SOCK_STREAM)

# build connection with the server and send message to it
clientSocket.connect(serverAddress)

print(clientSocket.getsockname())

#Log in to server
print("Please login to the server. (Case sensitive)")
login_flag = 0
username = None
while True:
    if not username:
        username = input("Username: ")
    password = input("Password: ")
    login_envelope = smp.SMP(
        CLIENT_IP,
        clientUDPPort,
        serverHost,
        serverPort,
        "AUTH",
        f"{username}\n{password}"
    )
    
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
    elif outcome[0] == "TIMEOUT":
        print(outcome[1])
        exit(0)
    else:
        print("Unknown error\nServer message: ", outcome[0])

print("Successfully logged in")

input_message = """Enter one of the following commands: [/msgto, /activeuser, /creategroup, /joingroup, /groupmsg, /p2pvideo, /logout]: """

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

    message = message.split()
    cmd = message[0]
    if cmd == "/msgto":
        print("This feature has not been implemented yet.")
    elif cmd == "/activeuser":
        command_envelope.cmd = "USER"
        command_envelope.msg = username
    elif cmd == "/creategroup":
        print("This feature has not been implemented yet.")
    elif cmd == "/joingroup":
        print("This feature has not been implemented yet.")
    elif cmd == "/groupmsg":
        print("This feature has not been implemented yet.")
    elif cmd == "/p2pvideo":
        print("This feature has not been implemented yet.")
    elif cmd == "/logout":
        command_envelope.cmd = "OUT"
        command_envelope.msg = username
    elif cmd == "/q":
        print(f"See you later {username}!")
        break
    else:
        print(f"Unknown command has been input.")
        continue
    

    clientSocket.sendall(smp.encode_message(command_envelope))

    # receive response from the server
    # 1024 is a suggested packet size, you can specify it as 2048 or others
    receivedMessage = smp.decode_message(clientSocket.recv(1024))



    if receivedMessage.cmd == "OUT":
        print(f"See you later {username}!")
        break
    elif receivedMessage.cmd == "USER":
        print(receivedMessage.msg)


# close the socket
clientSocket.close()
