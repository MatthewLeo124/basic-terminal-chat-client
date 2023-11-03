import datetime
import logging
import queue
import time
import sys
logging.basicConfig(format='%(asctime)s %(message)s', datefmt='%d/%m/%Y %H:%M:%S')


"""
Log types
LOGIN

    Active user sequence number; timestamp; username; client IP address;
    client UDP server port number
    1; 01 Jun 2022 21:30:04; Yoda; 129.64.1.11; 6666

Private message

    messageNumber; timestamp; username; message
    1; 01 Jun 2022 21:39:04; Yoda; do or do not, there is no try

Group chat:
    messageNumber; timestamp; username; message
    1; 01 Jun 2022 21:39:04; Yoda; do or do not, there is no try
"""

#datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
def run_logging(log_queue: queue.Queue):
    stdoutLogger = logging.getLogger("stdoutLogger")
    #if not stdoutLogger.handlers:
        #stdoutHandler = logging.StreamHandler(sys.stdout)
        #stdoutLogger.addHandler(stdoutHandler) 
    stdoutLogger.setLevel(logging.INFO) #Set handler on the logger not the handler to properly set the output

    group_chat_handlers = {} #{'group_chat_name' : logger}

    cmd = None
    #{command:string, time:string, msg_num:int, msg:string}
    #{command:string, userdata: dict}
    with open("messagelog.txt", "a+") as msg_log:
        while True:
            task = log_queue.get()
            #Server is shutting down, signal thread shutdown
            if task['cmd'] == "SHUTDOWN":
                stdoutLogger.info("SHUTDOWN: Server shutdown flag received, logger shutting down")
                break

            #General stdout message
            #{command:string, msg:string}
            elif task['cmd'] == "GEN":
                stdoutLogger.info(f"GEN: {task['msg']}")

            #User logs in
            #{command:string, username:string, ip:string, udp_port:string, user_number: int}
            elif task['cmd'] == "LOGIN":
                curr_time = datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
                message = f"{task['user_number']}; {curr_time}; {task['username']}; {task['ip']}; {task['udp']}"
                write_userlog(task['cmd'], message)
                stdoutLogger.info(f"LOGIN: {task['username']} has logged in from {task['ip']}:{task['udp']}")

            #User logs out
            #{command:string, username:string, msg:string}
            elif task['cmd'] == "LOGOUT":
                write_userlog(task['cmd'], task['username'])
                stdoutLogger.info(f"LOGOUT: {task['username']} has logged out")

            #User sends a private message
            #{command:string, time:string, msg_num:int, msg:string}
            #User sends a group message
            #{command:string, time:string, group:string, msg_num:int, msg:string}
            elif task['cmd'] == "MSG":
                
                #group message
                if 'group' in task:
                    #Create files and loggers for respective group chats
                    log_msg = f"MESSAGE: TO BE IMPLEMENTED"
                    stdoutLogger.info(log_msg)
                
                #private message
                else:
                    log_msg = f'{task["sender"]} sent a message to {task["recipient"]} "{task["message"]}" at {task["time"]}'
                    file_log = f"{task['msg_number']}; {task['time']}; {task['sender']}; {task['message']}"
                    msg_log.write(file_log + '\n')
                    msg_log.flush() #need to flush the buffer as its usually flushed once its closed.
                    stdoutLogger.info(log_msg)

            else:
                stdoutLogger.error(f"Unknown log command {task['cmd']}")

    return


#Dictionary attributes
#    'user_number': user[0],
#    'login_time': user[1],
#    'username': user[2],
#    'ip': user[3],
#    'udp': user[4]
def write_userlog(cmd: str, target: str):
    if cmd == "LOGIN":
        with open("userlog.txt", "a+") as f:
            f.write(target + '\n')

    else: #cmd == "LOGOUT"
        #Build list of current users
        current_users = []
        with open("userlog.txt", "a+") as f:
            f.seek(0)
            for line in f:
                user = line.strip().split('; ')
                current_users.append(user)

            #wipe file
            f.seek(0)
            f.truncate(0)

            #write to file
            seen = False
            for user in current_users:
                if user[2] == target:
                    seen = True
                    continue
                if seen:
                    user[0] = str(int(user[0]) - 1)
                f.write("; ".join(user) + '\n')
    return
