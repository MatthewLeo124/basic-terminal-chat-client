import asyncio
import logging
import socket
import sys

#TODO List
"""
1) Implement logger
2) Implement server
    2.1) Implement functions for each of the functions
"""

"""
Simple messaging protocol SMP
HEADER
FROM XYX\r\n
TO YXY\r\n
CMD ZZZ\r\n
MSG\r\n\r\n
"""



class Server:
    def __init__(self, port: int, retries: int):
        self.n_retries = retries
        self.address = ("127.0.0.1", port)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.clients = {}
        self.socket.bind(self.address)
        self.socket.listen()

    
    #User authentication and lockout feature
        #User will send username and password
        #n_retires of incorrect logins per username before 10 second timeout so no one can log in to that username during timeout
        #'database' is credentials.txt file
    async def login(self):
        pass

    #List all active users (users connected to the server)
        #Send username, timestamp of when they became active, ip address, TCP+UDP port numbers
        #Exclude caller
        #If no one else return "no other active user"
    async def list_active(self):
        pass

    #Send message to target specified
    #message number, timestamp, username, log message 
    #message numbers are global
    #return success / failure to client in form of "message sent at <timestamp>"
    async def send_message(self):
        pass

    #Create a group for a group of users
    async def create_group(self):
        pass

    #Add user to a group
    async def join_group(self):
        pass

    #Peer wants to send file to another peer
    #Will ping server for that users UDP port
    async def send_file(self):
        pass
    
    async def handle_client(self, loop, client_socket, address): 
        data = await loop.sock_recv(client, 1024)
        #Handle client data

    async def run(self):
        loop = asyncio.get_event_loop()
        while True:
            client, address = await loop.sock_accept(self.socket)
            await asyncio.create_task(self.handle_client(loop, client, address))
            

if __name__ == "__main__":
    #if len(sys.argv) != 3:
    #    print("Insufficient number of arguments, I require only a TCP port and number of failed attempts!")
    #    exit(1)

    tcp_port = int(sys.argv[1])
    attempts = int(sys.argv[2])
    
    #if attempts < 1 or attempts > 6:
    #    print("Invalid amounts of attempts, please choose a number 0<x<6")
    #    exit(1)

    #run the server
    server = Server(tcp_port, attempts)
    asyncio.run(server.run())

