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
        self.socket.bind(self.address)
    
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

    async def run(self):
        self.socket.listen()
        self.socket.accept()


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Insufficient number of arguments, I require only a TCP port and number of failed attempts!")
        exit(1)
    tcp_port = int(sys.argv[1])
    attempts = int(sys.argv[2])
    if 1 < attempts < 6

    #run the server
    server = Server(tcp_port, attempts)
    asyncio.run(server.run())

