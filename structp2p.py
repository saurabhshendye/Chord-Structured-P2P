import socket, sys, random, hashlib, os, threading, logging
from socket import error as Socket_error
import time
# -----------------------------------------------------------------
# global variables
# -----------------------------------------------------------------
# connection related
BS_IPAddress = sys.argv[1]
# print("BS_IPAdress", BS_IPAddress)
BS_port = int(sys.argv[2])
BS_address = (BS_IPAddress, BS_port)
#print("BS_port", BS_port)
# ---------------------
# Node Identity related
my_ip = str(sys.argv[3])
#print("my_ip", my_ip)
my_port = int(sys.argv[4])
#print("my_port", my_port)
laddress = (my_ip, my_port)
#print("laddress", laddress)
# ---------------------
#registered under username
user = "vp"
#list of all nodes in the network
#network_node_list_org = list()
network_nodes_list = list()
##list of network nodes IP:PORT hash --> INT representation
#network_nodes_inthash = list()
#list to hold node fingertable
finger_table_master = list()
#list to hold key_list --> simple list of hex keys
resource_key = list()
#keyspace <- hash subset bitsize
keyspace = 20
#holds the predecessor ((IP, PORT), 'hash') tuple
node_predecessor = tuple
#holds the predecessor ((IP, PORT), 'hash') tuple
node_successor = tuple
#max hops for killing packets - avoids infinite packet circulation
max_hops = 3
#variable counter for tracking upfin_ exit acknowledgment
exit_ack = 0
# --------------------------------------------------------------------
# Getting IP address - handy for local simulation
# IP = os.popen('ifconfig wlan0 | grep "inet\ addr" | cut -d: -f2 | cut -d" " -f1')
# my_ip = IP.read()[:-1]
# ---------------------
# Resource realted:
#number of resouces per node
number_of_entries = int(sys.argv[5])
#list to hold all (resouce,key) tuple
resource_key = list()
#list to hold all resources
all_resources = list()
#node specific resource list
loc_rsc = list()
# ---------------------hashing
# Logging related
log_file = "node.log"
# check if a log file exists:
try:
    os.remove("node.log")
except OSError:
    # print("File not present")
    pass    
#creating log_file on this node
logging.basicConfig(filename=log_file,level=logging.DEBUG, format='%(created)f %(message)s')
# ------------------------------------------------------------------
# Creating the Threaded-Server Socket Class
# This will only be used for serving the requests
# Comment - This class will only be used while communicating with other nodes.
class Server(threading.Thread):
    def __init__(self, client_socket, tobeSent, addr):
        threading.Thread.__init__(self)
        self.client_socket = client_socket
        self.address = addr
        self.tobeSent = tobeSent
    def run(self):
        try:
            self.client_socket.send(self.tobeSent)
        except (RuntimeError, TypeError, NameError, Socket_error) as Err:
            print("socket error. Pipe closing")

def user_in():
    global finger_table_master, node_successor, resource_key, network_nodes_list
    #print("Taking User input")
    # Here we need to have inputs like exit, search, show finger table
    # show resources etc.
    while True:
        user_input = raw_input('Enter Command thread: ')
        #print(ip)
        if user_input == "EXIT ALL":
           # Addition EXIT ALL condition even for multiple nodes for easy of running it
           if not network_nodes_list:
               command = exitall()
               # C_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
               # C_sock.connect((BS_IPAddress, int(BS_port)))
               # command = del_ip()
               # reg_ack = C_sock.recv(4096)
               # C_sock.shutdown(socket.SHUT_RDWR)
               # C_sock.close()
               response_processor(command, laddress)
               # os._exit(os.EX_OK)
           else:
               command = exitall()
               for node in network_nodes_list:
                   print("Sending update to " + str(node))
                   sending(node[0], node[1], command)

               C_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
               C_sock.connect((BS_IPAddress, int(BS_port)))
               # command = del_ip()
               # reg_ack = C_sock.recv(4096)
               # C_sock.shutdown(socket.SHUT_RDWR)
               # C_sock.close()
               # os._exit(os.EX_OK)
               response_processor(command, laddress)
        elif user_input == "EXIT":
            #print("exit caught")
            if not network_nodes_list:
                # only this node in network
                # issue unregister seqeunce
                C_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                C_sock.connect((BS_IPAddress, int(BS_port)))
                command = del_ip()
                # send node del command to BS
                C_sock.send(command)
                # receive response
                reg_ack = C_sock.recv(4096)
                C_sock.shutdown(socket.SHUT_RDWR)
                C_sock.close()
                # Pass it to a response processor
                response_processor(reg_ack, BS_address)
            else:
                print("Give keys, send update to fingers and EXIT")
                #                #give keys to successor:
                command = giveKey(len(resource_key), resource_key)
                print("Send {} to successor".format(command))
                sending(node_successor[0], node_successor[1], command)
        else:
            response_processor(user_input, laddress)

# ------------------------------------------------------------------
# ------------------------------------------------------------------
# Import,hash,search,send and receive functions for this node
def importing():
    """ This function is used for importing resources in the node.
        This method uses a num_of_ehashingntries which is a passed as an argument.
        This sets the number of resources it randomly selects from the
        resource file.
    """
    global all_resources
    # Importing the resource file and reading by line
    f = open("resources_sp2p.txt", 'r')
    all_resources = f.readlines()
    # filtering allowed resources
    all_resources = all_resources[3:111]
    f.close()
    # creating empty list to hold local node resources
    loc_resources = list()
    # sample random entries from the all_resource list
    loc_resources = random.sample(all_resources, number_of_entries)
    # debug
    #print(loc_resources)
    for i in range(len(loc_resources)):
        loc_resources[i] = loc_resources[i].rstrip('\r\n')
    return loc_resources
def hashing(tobeHashed, mode):
    """ This function is used for hashing nodeID (IP PORT) & filenames.
        mode flag is used to seperate hasing strategy for nodeID & file names
        We are choosing 20 bits for representing a subset of each hash key.
    """
    if mode == 1:
        # this mode is for hashing nodeID
        # In this case, the tobeHased is a tuple
        tobeHashed = tobeHashed[0] + " " + str(tobeHashed[1])
        hash_object = hashlib.md5(tobeHashed)
        # returns a 20 bit hash subset
        # print("hash type:" ,type(hash_object.hexdigest()))
        return hash_object.hexdigest()[:-27]
    elif mode == 2:
        # this mode is for hashing filenames
        # converting name to lower case and removing \r\n
        tobeHashed = tobeHashed[:-2].lower()
        # debug
        # print(tobeHashed)
        hash_object = hashlib.md5(tobeHashed)
        # returns a 20 bit hash subset
        return hash_object.hexdigest()[:-27]

def print_resource_list():
    global resource_key
    #print(resource_key)
    # these two variables are used to maintaining indentation while printing
    space = ' '
    # find out the longest string name:
    if len(resource_key) != 0:
        print("------------------------------------------")
        print("Resource list available at this node and their hash values:\n")
        temp_c = list()
        for i in resource_key:
            temp_c.append(i[0])
        max_len = len(sorted(temp_c, key=len)[-1])+5
        for key in resource_key:
            # replacing "_" by " " just for the purpose of printing
            #key_list.append(hashing(loc_rsc[i], 2))
            #print(key)
            print(key[0] + (max_len - len(key[0])) * space + key[1] + (max_len - len(key[1])) * space + str(key[2]))
            print("------------------------------------------")
    else:
        pass

#
# def print_resource_list():
#     global resource_key
#     print("------------------------------------------")
#     print("Resource list available at this node and their hash values:\n")
#     if not resource_key:
#         print("No resources found on this node")
#     else:
#         # these two variables are used to maintaining indentation while printing
#         space = ' '
#         max_len = 0
#         # find out the longest string name:
#         max_len = len(sorted(resource_key, key=len)[-1]) + 20
#         for resource in resource_key:
#             print(resource[0] + " " + str(resource[1]) + " " + str(resource[2]))
#         # for i in range(0, len(loc_rsc)):
#         #     # replacing "_" by " " just for the purpose of printing
#         #     #key_list.append(hashing(loc_rsc[i], 2))
#         #     print(loc_rsc[i] + (max_len - len(loc_rsc[i])) * space + hashing(loc_rsc[i], 2) + (max_len - len(loc_rsc[i])) * space + str(int(hashing(loc_rsc[i], 2), 16)))
#         #     i = i + 1
#     print("------------------------------------------")

# ----------------SENDING FUNCTIONS---------------------------------------------------------    
def sending(ip, port, msg):
    #logging sending_msg
    logging.info('[OUTPUT] '+ msg)
    # print("entered sending")
    # ---------------------
    # Connect the socket to the port where the server is listening
    C_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # print("New Socket object Created")
    C_sock.connect((ip, port))
    # print("soc connected to :" ,(ip, port))
    C_sock.send(msg)
    # print("msg sent")
    C_sock.shutdown(socket.SHUT_RDWR)
    C_sock.close()
    # print("C_sock closed")

# ----------------FINGER TABLE RELATED FUNCTIONS---------------------------------------------------------    
def create_first_node_finger_table():
    global finger_table_master
    finger_table = list()
    for i in range(1, keyspace + 1):
        temp = []
        #Start value
        start_value = self_hash_int + (2**(i-1))%(2**keyspace)
        if start_value >= 2**keyspace:
            start_value = abs(2**keyspace - start_value)
        temp.append(start_value)
        #Interval tuple
        end_value = self_hash_int + ((2**(i))%(2**keyspace))
        if end_value >= 2**keyspace:
            end_value = abs(2**keyspace - end_value)
        temp.append((start_value, end_value))
        #Finger successor
        temp.append(node_successor[3])
        #IP
        temp.append(laddress[0])
        #Port
        temp.append(laddress[1])
        #
        #appending list to the finger table
        finger_table.append(temp)
    finger_table_master = finger_table
    print_finger_table(finger_table_master)

def create_node_finger_table():
    global my_ip,my_port,self_hash_int,self_hash,node_predecessor, node_successor,network_nodes_list, finger_table_master
    finger_table = list()
    temp_network_nodes_list = list()
    #print("before calling get_neighbours", network_nodes_list)
    node_successor, node_predecessor = get_neighbours() 
    #print("node_predecessor", node_predecessor) 
    #print("node_successor", node_successor) 
    #Finding Finger_successor
    #we first need to add this node to a temp node_list
    temp_network_nodes_list = network_nodes_list[:]
    my_list_entry = ((my_ip, my_port,self_hash, self_hash_int))
    temp_network_nodes_list.append(my_list_entry)
    #Now sorting the node list
    temp_network_nodes_list.sort(key=lambda x: x[3]) 
    #print("temp_network_nodes_list", temp_network_nodes_list)
    for i in range(1, keyspace + 1):
        finger_successor = None
        temp = list()
        #Start value
        start_value = (self_hash_int + 2**(i-1))%(2**keyspace)
        if start_value >= 2**keyspace:
            start_value = abs(2**keyspace - start_value)
        #print "start_value"
        #print(start_value)
        temp.append(start_value)
        #Interval tuple
        end_value = (self_hash_int + (2**(i)))%(2**keyspace)
        if end_value >= 2**keyspace:
            end_value = abs(2**keyspace - end_value)
        temp.append((start_value, end_value))
        #Finding the finger successor
        finger_successor = get_finger_successors(start_value, temp_network_nodes_list)
        #print("finger_successor", finger_successor)
        temp.append(finger_successor[3])
        #IP
        temp.append(finger_successor[0])
        #Port
        temp.append(finger_successor[1])
        #appending list to the finger table
        finger_table.append(temp)
    finger_table_master = finger_table
    print_finger_table(finger_table_master)
    #sending updates to all other nodes:
    #send_updates_to = get_tobeupdated_nodes(temp_network_nodes_list)
    #create update finger table command:
    update_command = upfin(0,self_hash)
    for node in network_nodes_list:
        print("Sending update to " + str(node))
        sending(node[0],node[1], update_command)
    #now initiating key exchange:
    print("Initiating key exchange")
    key_exchange()
    take_my_keys()

def update_fingertable(new_node, mode):
    global my_ip,my_port,self_hash_int,self_hash, finger_table_master
    finger_table = list()
    temp_network_nodes_list = list()
    global node_predecessor, node_successor
    node_successor, node_predecessor = get_neighbours() 
    #print("node_predecessor", node_predecessor) 
    #print("node_successor", node_successor) 
    #Finding Finger_successor
    #we first need to add this node to a temp node_list
    temp_network_nodes_list = network_nodes_list[:]
    my_list_entry = ((my_ip, my_port,self_hash, self_hash_int))
    temp_network_nodes_list.append(my_list_entry)
    #Now sorting the node list
    temp_network_nodes_list.sort(key=lambda x: x[3]) 
    #print("temp_network_nodes_list", temp_network_nodes_list)
    for i in range(1, keyspace + 1):
        finger_successor = None
        temp = list()
        #Start value
        start_value = (self_hash_int + 2**(i-1))%(2**keyspace)
        if start_value >= 2**keyspace:
            start_value = abs(2**keyspace - start_value)
        #print "start_value"
        #print(start_value)
        temp.append(start_value)
        #Interval tuple
        end_value = (self_hash_int + (2**(i)))%(2**keyspace)
        if end_value >= 2**keyspace:
            end_value = abs(2**keyspace - end_value)
        temp.append((start_value, end_value))
        #Finding the finger successor
        finger_successor = get_finger_successors(start_value, temp_network_nodes_list)
        #print("finger_successor", finger_successor)
        temp.append(finger_successor[3])
        #IP
        temp.append(finger_successor[0])
        #Port
        temp.append(finger_successor[1])
        #appending list to the finger table
        finger_table.append(temp)
    finger_table_master = finger_table
    print_finger_table(finger_table_master)
    #now initiating key exchange:
    print("Initiating key exchange")
    take_my_keys()
    key_exchange()

#    #decide whether to fwd the update to its predecessor
#    #check if this update was not received from its predecessor:
#    if node_predecessor[0] != new_node[0]:
#        #sending updates to its predecessor:
#        #create update finger table command:
#        new_node_IP = new_node[0]
#        new_node_port = new_node[1]
#        new_node_hash = new_node[2]
#        update_fwd_command = upfin_fwd(mode,new_node_IP,new_node_port,new_node_hash)
#        #sending update to predecessor
#        #print("sending update to predecessor" + str(node_predecessor))
#        sending(node_predecessor[0],node_predecessor[1], update_fwd_command)
#    else:
#        print("updated by predecessor so no need to send back update")
#        print("no need to update or send update to others")
def get_neighbours():
    global network_nodes_list, self_hash_int, my_self
    #print("get neighbours")
    #print("network_nodes_list", network_nodes_list)
    #creating a list for calculating distances from each other node in the n/w
    diff_list = list()
    if len(network_nodes_list) != 0:
        for i in network_nodes_list:
            #print("iteration node:",i)
            node_ID = i[3]
            #print("self_hash_int", self_hash_int)
            #print("node_ID", node_ID)
            difference  = self_hash_int - node_ID
            #print("difference", difference)
            diff_list.append(difference)    
        #print("diff_list",diff_list) 
        pos_list = list()
        neg_list = list()
        #sorting
        for i in diff_list:
            if i > 0:
                pos_list.append(i)
            else:
                neg_list.append(i)
        #print("pos_list", pos_list)
        #print("neg_list", neg_list)    
        #return based on values in neg and pos lists
        if len(pos_list) != 0 and len(neg_list) == 0:
            #print("case1")
            #finding the successor
            succ_index = max(pos_list)
            succ = network_nodes_list[diff_list.index(succ_index)]
            #finding the predecessor
            prede_index = min(pos_list)
            prede = network_nodes_list[diff_list.index(prede_index)]
            return succ, prede
        elif len(pos_list) == 0 and len(neg_list) != 0:
            #print("case2")
            #finding the successor
            succ_index = max(neg_list)
            succ = network_nodes_list[diff_list.index(succ_index)]
            #finding the predecessor
            prede_index = min(neg_list)
            prede = network_nodes_list[diff_list.index(prede_index)] 
            return succ, prede
        else:
            #print("case3")
            #finding the successor
            succ_index = max(neg_list)
            succ = network_nodes_list[diff_list.index(succ_index)]
            #finding the predecessor
            prede_index = min(pos_list)
            prede = network_nodes_list[diff_list.index(prede_index)]
            return succ, prede
    else:
        #print("no node in network node list")
        succ = my_self
        prede = my_self
        return succ, prede

def get_finger_successors(finger_start, node_list):
    #print("get_finger_successors")
    #creating a list for calculating distances from each other node in the n/w
    diff_list = list()
    for i in node_list:
        nodeHash = i[2]
        node_ID = int(nodeHash, 16)
        difference  = finger_start - node_ID
        diff_list.append(difference)    
    #print diff_list
    pos_list = list()
    neg_list = list()
    #sorting
    for i in diff_list:
        if i > 0:
            pos_list.append(i)
        else:
            neg_list.append(i)
    #return based on values in neg and pos lists
    if len(pos_list) != 0 and len(neg_list) == 0:
        #print("case1")
        #finding finger successor
        succ_index = max(pos_list)
        succ = node_list[diff_list.index(succ_index)]
        return succ
    elif len(pos_list) == 0 and len(neg_list) != 0:
        #print("case2")
        #finding the successor
        succ_index = max(neg_list)
        succ = node_list[diff_list.index(succ_index)]
        return succ
    else:
        #print("case3")
        #finding finger successor
        succ_index = max(neg_list)
        succ = node_list[diff_list.index(succ_index)]   
        return succ

def print_finger_table(table):
    """ This functions is used for formating and printing the finger table.
        The finger table is stored as a n x 5 global list.
    """
    #print("finger_table", table)
    global self_hash, node_predecessor, node_successor
    print ("-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------")
    print ("fingertable - " + self_hash + " " + "Predecessor: " + node_predecessor[0] + " " + str(node_predecessor[1]) + " " + node_predecessor[2] + " " + str(node_predecessor[3]) + " " + "Successor: "  + node_successor[0] + " " + str(node_successor[1]) + " " + node_successor[2] + " " + str(node_successor[3]))
    print ("------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------")
    space1 = '__'    
    space2 = '_'
    max_len = 0
    temp_table = list()
    for i in table:
        temp_table.append(str(i[1]))
    #find out the longest string name(usually longest IP string) in the temp_table:
    max_len = len(sorted(temp_table, key=len)[-1]) + 1
    print ("index"  + (max_len - len("index"))*space1 + "Start" + (max_len - len("Start"))*space1 + "Interval" + (max_len - len("Interval"))*space1 + "Successor" + (max_len - len("Successor"))*space1 + "IP:PORT")
    for idx, i in enumerate(table):
        print (str(idx+1) + (max_len - len(str(idx+1)))*space2 + hex(i[0])[2:] + " " + str(i[0]) + (max_len - len(str(i[0])))*space2 + str((hex(i[1][0])[2:],hex(i[1][1])[2:])) + " " + str(i[1])  + (max_len - len(str(i[1])))*space2 + hex(i[2])[2:] + " " + str(i[2]) + (max_len - len(str(i[2])))*space2 + str(i[3])+ ":"+ str(i[4]))
    print ("------------------------------------------------------------")

def print_node_list():    
    global network_nodes_list
    #print("network_nodes_list", network_nodes_list)
    #printing the network node list after reg response:
    print ("------------------------------------------")
    print ("Printing node list")
    print ("------------------------------------------")
    print("IP address      Port  Hash decimal_Hash")
    temp = ""
    for i in range(0, len(network_nodes_list)):
        temp = temp + network_nodes_list[i][0] + " " + str(network_nodes_list[i][1]) + " " + network_nodes_list[i][2] + " " + str(network_nodes_list[i][3])
        print (temp)
        #clear temp
        temp = ""
    print ("------------------------------------------")
    
def key_exchange():
    global resource_key,node_predecessor,self_hash_int, finger_table_master
    #This is for exchanging keys:
    #first find your if keys belongs to you:
    my_keys = list()
    not_my_keys = list()
    for key in resource_key:
        if node_predecessor[3] > self_hash_int:
            if node_predecessor[3] < key[2] < 1048576 or 0 <= key[2] < self_hash_int:
                my_keys.append(key)
            else:
                pass
        elif node_predecessor[3] < key[2] < self_hash_int:
            my_keys.append(key)
        else:
            not_my_keys.append(key)
    #print("my_keys",my_keys)
    #print("not_my_keys",not_my_keys)

    #find the node to send the key and create a list of keys and their owners
    owners = list()
    for not_my_key in not_my_keys:
        #check for the finger that can contain this key
        for finger in finger_table_master:
            if finger[1][0] > finger[1][1]:
                if finger[1][0]< not_my_key[2] < 1048576 or 0 <= not_my_key[2] < finger[1][1]:
                    owners.append((not_my_key, finger))
                    break
                else:
                    pass
            elif finger[1][0]< not_my_key[2] < finger[1][1]:
                owners.append((not_my_key, finger))
                break
        resource_key.remove(not_my_key)

    #print owners:
    #print("owners", owners)
    #Sending keys to owners
    for owner in owners:
        file_key = owner[0][1]
        file_name = owner[0][0]
        owner_ip = owner[1][3]
        owner_port = int(owner[1][4])
        command  = add(file_key,file_name)        
        sending(owner_ip,owner_port,command)

def take_my_keys():
    # ack the successor to handover all the keys belonging to me
    global node_successor
    command = getky()
    sending(node_successor[0], node_successor[1], command)


# ----------------USAGE AND OTHER MENU OPTIONS---------------------------------------------------------
def usage():
    print("\nAvailable options for use: [<SEARCH>] Usage: SEARCH filename\n\t\t\t[<KEYTABLE>] Usage: KEYTABLE\n\t\t\t[<FINGERTABLE>] Usage: FINGERTABLE\n\t\t\t[<GENERATE QUERY>] Usage: GENERATE QUERY <zipf_factor> <Num_of_Queries> <filename>\n\t\t\t[<SEND QUERY>] Usage: SEND QUERY <filename>\n\t\t\t[<EXIT>] Usage:EXIT\n\t\t\t[<EXIT ALL>] Usage:EXIT ALL\n\t\t\t[<DETAILS>] Usage:DETAILS\n\t\t\t[<HELP>]  Usage: HELP\n\t\t\t[<GET RESOURCE LIST>]  Usage: GET RESOURCE LIST")
# ------------------------------------------------------------------
# creating a list of functions for message construction:
# Section A: Register/Unregister with BS
def reg():
    """ This function is used for constructing reg message.
        Sample message : 0027 REG 10.0.0.198 1512 vpnetwork_nodes_list
    """  # print "------------------------------------------"
    command = "REG " + my_ip + " " + str(my_port) + " " + user
    command = str(len(command) + 5).zfill(4) + " " + command
    return command
# Section B: Update finger table 
def upfin(types, key):
    """ This function is used for constructing update finger table message.
        Sample message : 0034 UPFIN 0 10.0.0.198 1512 7e563
    """
    global my_ip, my_port
    command = "UPFIN " + str(types) + " " + my_ip + " " + str(my_port) + " " + key
    command = str(len(command) + 5).zfill(4) + " " + command
    return command
    
#upfin_fwd(0,new_node[0],new_node[1],new_node[2])    
def upfin_fwd(types, fwd_node_ip, fwd_node_port, fwd_node_hash):
    """ This function is used for constructing update finger table message which is to be forwarded.
        Sample message : 0034 UPFIN 0 10.0.0.198 1512 7e563
    """
    command = "UPFIN " + str(types) + " " + fwd_node_ip + " " + str(fwd_node_port) + " " + fwd_node_hash
    command = str(len(command) + 5).zfill(4) + " " + command
    return command
def upfinok(mode):
    command = "UPFINOK " + str(mode)
    command = str(len(command) + 5).zfill(4) + " " + command
    return command
# Section C: GET KEYS FROM SUCCESSOR

def getky():
    global self_hash, node_predecessor
    command = "GETKY" + " " + self_hash + " " + node_predecessor[2]
    command = str(len(command) + 5).zfill(4) + " " + command
    return command

def getKeyOk(num, resources_key_tobesent):
    global my_ip, my_port
    command = "GETKYOK" + " " + str(num)
    if num == 0:
        command = str(len(command) + 5).zfill(4) + " " + command
        return command
    else:
        command = command + " " + my_ip + " " + str(my_port)
        for resource in resources_key_tobesent:

            command = command + " " +  resource[0].replace(" ", "_") + " " + resource[1]

        command = str(len(command) + 5).zfill(4) + " " + command
        return command
#Section D: Give keys to successor
def giveKey(num, array):
    command = "GIVEKY" + " " + str(num)
    if num == 0:
        command = str(len(command) + 5).zfill(4) + " " + command
        return command
    else:
        command = command + " " + my_ip + " " + str(my_port)
        for entry in array:

            command = command + " " +  entry[0].replace(" ", "_") + " " + entry[1]

        command = str(len(command) + 5).zfill(4) + " " + command
        return command
def giveKeyOk():
    command = "GIVEKYOK 0"
    command = str(len(command) + 5).zfill(4) + " " + command
    return command
#Section E: Add a key to the Network
def add(key, filename):
    command = "ADD " + my_ip + " " + str(my_port) + " " + key + " " + filename.replace(" ", "_")
    command = str(len(command) + 5).zfill(4) + " " + command
    return command
def addok():
    command = "ADDOK 0"
    command = str(len(command) + 5).zfill(4) + " " + command
    return command
#Section F: Search for a Key
def ser(hash):
    hops = max_hops
    command = "SER" + " " + my_ip + " " + str(my_port) + " " + str(hash) + " " + str(hops)
    command = str(len(command) + 5).zfill(4) + " " + command
    return command
def serok(return_list,recv_hops,mode):
    #return list is a string list of nrow x 4 col
    #This matix columns are IP, Port,Filename all stored as strings
    #Ref_list = [['10.0.0.198', '1501', 'The_Time_Machine']]
    #mode 0 for not found and mode 1 for found
    if mode == 0:
        command = "SEROK " + str(mode) + " " + str(recv_hops) + " " + str(len(return_list)) + " " + return_list[0]
        command = str(len(command) + 5).zfill(4) + " " + command
    else:       
        command = "SEROK " + str(mode) + " " + str(recv_hops) + " " + str(len(return_list)) + " "
        temp = ""
        for i in range(0, len(return_list)):
            for j in range(0, 2):
                if j == 1:
                    #replacing " " by "_" to facilitate parsing on receiving end
                    temp = temp + return_list[i][j].replace(" ", "_") + " "
                else:
                    temp = temp + return_list[i][j] + " "
                    command = command + temp[:-1]
                    command = str(len(command) + 5).zfill(4) + " " + command
    #debug
    #print (command)
    return command  
#Section G: Exit from Network
def del_ip():
    global my_ip, my_port, user
    command = "DEL IPADDRESS " + my_ip + " " + str(my_port) + " " + user
    command = str(len(command) + 5).zfill(4) + " " + command
    return command
def exitall():
    command = "EXIT ALL"
    command = str(len(command) + 5).zfill(4) + " " + command
    return command
# ------------------------------------------------------------------
# Error handling functions:
def error_code_description(response):
    response = response[5:]
    error_codes = ['BS REQ -9999', 'Unknown comand, undefined characters to Bootstrapper.', 'REGOK ' + user + ' -1',
                   'Unknown REG command', 'REG OK 9999', 'Error in registering', 'REGOK ' + user + ' 9998',
                   'Already registered with Bootstrapper', 'DEL IPADDRESS OK -1', 'Error in DEL command',
                # forward = int(self_hash,16)       'DEL UNAME OK -1', 'Error in DEL command', 'DEL OK -1', 'Error in DEL command',
                   'DEL IPADDRESS OK 9998', 'IPAddress + Port not registered for specified username',
                   'DEL UNAME OK 9999', 'username not registered with bootstrapper', 'REGOK ss 9998']
    # searching response (which may be subset of the stored response)in error_codes string list
    try:
        error_msg = error_codes[error_codes.index(response) + 1]
        print("\n" + error_msg)
        return 1
    except ValueError:
        return 0
#-----------------Response processing------------------------------------------------------------------
def reg_parser(response):
    """This function is for parsing the regok response received from the serevr.
        There are two types of regok responses received.
        Type1: When the registering node is the first node registering with the BS.
               This is handled using code in the flag == 4 condition.
        Type2: When the regi	stering node is not the first node in the system.
               This is handled using code in the else condition.
    """
    global node_predecessor,node_successor,network_nodes_list
    #print("reg parser")
    byParts = response.split(" ")
    Num_nodes = int(byParts[3])
    #print("Number of nodes:" ,Num_nodes)
    if Num_nodes == 0:
        # This means it is the first node in the network so dont do anything after registering
        print("This is the first node in the network.")
        node_predecessor = my_self
        node_successor = my_self
        #print("network_nodes_list", network_nodes_list)
        print ("creating finger table at this node")
        create_first_node_finger_table()
    elif Num_nodes > 0:
        print("This is an intermediate node in the network.")
        for i in range(0, int(byParts[3]) * 2, 2):
            # creating a network node list @ each node
            node_IP = byParts[4+i]
            node_Port = int(byParts[5+i])
            node_Hash = hashing((byParts[4+i], int(byParts[5+i])), 1)
            node_Hash_decimal = int(node_Hash, 16)
            node_entry_tuple = (node_IP, node_Port, node_Hash, node_Hash_decimal)
            network_nodes_list.append(node_entry_tuple)
        #Sorting the network_node_list_org            
        network_nodes_list.sort(key=lambda x: x[3])
        #printing network_nodes_list
        print_node_list()        
        #Since this is not the first node in the system, it will simply create a finger table and send update requests
        #to the other concerned nodes.
        print ("creating finger table at this node")
        #Now sort the IPs based on hash values and create/update the finger table
        create_node_finger_table()

def upfin_parser(response):
    global network_nodes_list, finger_table_master
    #print("FINGER TABLE UPDATE REQUEST RECEIVED")
    byParts = response.split(' ')
    #print("printing received upfin request", byParts)
    if int(byParts[2]) == 0:
        # Addition of node to the network
        #first add the node to your node list
        node_added_IP = byParts[3]
        node_added_Port = int(byParts[4])
        node_added_hash = byParts[5]
        node_added_hash_int = int(byParts[5],16)
        node_added = (node_added_IP, node_added_Port, node_added_hash, node_added_hash_int)
        if node_added not in network_nodes_list:
            #print("I got to know of a new node")
            network_nodes_list.append(node_added)
            #Sorting the network_node_list_org            
            network_nodes_list.sort(key=lambda x: x[3])
            update_fingertable(node_added, 0)
            #send ack to the added node
            #print("Sending update finger table acknowledgement add mode")
            command  = upfinok(0)
            sending(byParts[3],int(byParts[4]),command)
            #print('Enter Command: ')
        else:
            print("no need to update")
    elif int(byParts[2]) == 1:
        # Node departing from the network
        node_departing_IP = byParts[3]
        node_departing_Port = int(byParts[4])
        node_departing_hash = byParts[5]
        node_departing_hash_int = int(byParts[5],16)
        node_departing = (node_departing_IP, node_departing_Port, node_departing_hash, node_departing_hash_int)
        if node_departing in network_nodes_list:
            #print("I got to know of a new node departing")
            network_nodes_list.remove(node_departing)
            # Removal of node from the network
            update_fingertable(node_departing, 1)
            #print("Sending update finger table acknowledgement remove mode")        
            #send ack to the going out node
            # command  = upfinok(1)
            # sending(byParts[3],int(byParts[4]),command)
            #print("Enter Command: ")
        else:
            print("no need to update")

def upfinok_parser(response):
    global exit_ack
    #print("This is updatefingertable response parser")
    part = response.split(' ')
    #print(part)
    if part[-1] == "0" and part[1] == "UPFINOK":
        print("FINGER TABLE UPDATED FOR REFLECTING THE NEW NODE ADDED")
    elif part[-1] == "1" and part[1] == "UPFINOK":
        print("FINGER TABLE UPDATED FOR REFLECTING THE NEW NODE THAT DEPARTED")
#        exit_ack = exit_ack - 1
#        if exit_ack == 0:
#            print("All nodes have been updated and hence now exit")
#            # issue unregister seqeunce
#            C_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#            C_sock.connect((BS_IPAddress, int(BS_port)))
#            command = del_ip()
#            # send node del command to BS
#            C_sock.send(command)
#            # receive response
#            reg_ack = C_sock.recv(4096)
#            # print("reg_ack: " ,reg_ack)
#            C_sock.shutdown(socket.SHUT_RDWR)
#            C_sock.close()
#            # Pass it to a response processor
#            response_processor(reg_ack, BS_address)

def del_parser(response):
    #print("This is a del parser")
    part = response.split(' ')
    #print(part)
    if ((part[-1] == "1") and (part[2] == "UNAME")):
        print("All nodes with username " + part[4] + " were unregistered successfully.")
        # exit node application
        os._exit(os.EX_OK)

    elif ((part[-1] == "1") and (part[2] == "IPADDRESS")):
        print("This node was unregistered successfully")
        # exit node application
        os._exit(os.EX_OK)

def add_parser(response):
    global resource_key, network_nodes_list, self_hash_int, node_predecessor,finger_table_master
    #print("Add parser")
    byParts = response.split(" ")
    file_name = byParts[-1]
    file_name  = file_name.replace("_", " ")
    file_key = byParts[4]
    file_key_int = int(file_key, 16)
    incoming_ip = byParts[2]
    incoming_port = int(byParts[3])
    #check if the key in in this nodes range
    if node_predecessor[3] > self_hash_int:
        if node_predecessor[3] < file_key_int < 1048576 or 0<= file_key_int < self_hash_int:
            #print("this is my key")
            #print(file_name)
            # add if it does not exist
            entry = (file_name, file_key, file_key_int)
            if entry not in resource_key:
                # make_entry = (file_name, file_key, file_key_int)
                resource_key.append(entry)
                # send ack to the source node:
                command = addok()
                sending(incoming_ip, incoming_port, command)
            else:
                pass
        else:
            pass
    elif node_predecessor[3] < file_key_int < self_hash_int:
        #print("this is my key")
        #print(file_name)
        # add if it does not exist
        entry = (file_name, file_key, file_key_int)
        if entry not in resource_key:
            # make_entry = (file_name, file_key, file_key_int)
            resource_key.append(entry)
            # send ack to the source node:
            command = addok()
            sending(incoming_ip, incoming_port, command)
        else:
            pass
    else:
        #print("not my key so I need to forward it to one of my fingers")
        for finger in finger_table_master:
            if finger[1][0] > finger[1][1]:
                #print("Range splitting:")
                if finger[1][0] < file_key_int < 1048576 or 0 <= file_key_int < finger[1][1]:
                    command = add(file_key, file_name)
                    sending(finger[3], finger[4], command)
                    break
                else:
                    pass

            elif finger[1][0] < file_key_int < finger[1][1]:
                command = add(file_key, file_name)
                sending(finger[3], finger[4], command)
                break

    # if node_predecessor[3] < file_key_int < self_hash_int:
    #     print("this is my key")
    #     print(file_name)
    #     #add if it does not exist
    #     if file_key_int not in resource_key:
    #         make_entry = (file_name,file_key,file_key_int)
    #         resource_key.append(make_entry)
    #         #send ack to the source node:
    #         command = addok()
    #         sending(incoming_ip,incoming_port,command)
    #     else:
    #         print("not my key so I need to forward it to one of my fingers")
    #         for finger in finger_table_master:
    #             if finger[1][0] > finger[1][1]:
    #                 print("Range splitting:")
    #                 if finger[1][0] < file_key_int < 1048576 or 0 <= file_key_int < finger[1][1]:
    #                     command = add(file_key, file_name)
    #                     sending(finger[3], finger[4], command)
    #                     break
    #             elif finger[1][0] < file_key_int < finger[1][1]:
    #                 command = add(file_key, file_name)
    #                 sending(finger[3], finger[4], command)
    #                 break

            # for finger in finger_table_master:
            #     if finger[1][0]< file_key_int < finger[1][1]:
            #         #Sending keys to respective finger
            #         command = add(file_key,file_name)
            #         sending(finger[4],finger[5],command)
            #         break

def addok_parser(response):
    part = response.split(' ')
    #print(part)
    if part[-1] == "0" and part[1] == "ADDOK":
        print("ADD OK RESPONSE RECEIVED")

def getkey_parser(response):
    global resource_key, node_predecessor, loc_rsc
    #print("Get key parser")
    byParts = response.split(" ")
    remote_node_hash = byParts[2]
    remote_node_hash_int = int(remote_node_hash, 16)
    remote_node_pred_hash = byParts[3]
    remote_node_pred_hash_int = int(remote_node_pred_hash, 16)
    send_these_keys = list()
    for key in resource_key:
        #print("remote_node_pred_hash_int", remote_node_pred_hash_int)
        #print("remote_node_hash_int", remote_node_hash_int)
        #print("key", key)
        if remote_node_hash_int < remote_node_pred_hash_int:
            #print("split range")
            # split range as this is zero cross over
            if remote_node_pred_hash_int < key[2] < 1048576 or 0 <= key[2] < remote_node_hash_int:
                #print("found key", key)
                send_these_keys.append(key)
        else:
            # no need to split range
            #print("no need to split range")
            if remote_node_pred_hash_int < key[2] < remote_node_hash_int:
                #print("found key", key)
                send_these_keys.append(key)
    #print("send_these_keys", send_these_keys)
    # send the keys to its predecessor:
    command = getKeyOk(len(send_these_keys), send_these_keys)
    sending(node_predecessor[0], node_predecessor[1], command)
    # remove keys after sending
    for sent_key in send_these_keys:
        resource_key.remove(sent_key)
    print("Updated resource list after sending keys to predecessor")
    print_resource_list()


def getkeyok_parser(response):
    global resource_key
    part = response.split(' ')
    num_of_keys = int(part[2])
    if num_of_keys == 0:
        print("No keys returned")
        #print("Enter Command: ")
    else:
        print("Received " + str(num_of_keys) + " keys from the successor")
        for i in range(5, len(part),2):
            # replacing "_" by a space in the string filename
            part[i] = part[i].replace("_", " ")
            file_name = part[i]
            file_hash = part[i+1]
            file_hash_int = int(part[i+1],16)
            res_tuple = (file_name, file_hash, file_hash_int)
            # converting to title case and then storing in keylist
            # part[i + 1] = part[i + 1].title()
            # temp[j] = part[i + 3]
            if res_tuple not in resource_key:
                #resource_key.append(part[i])
                resource_key.append(res_tuple)
        print("Updated resource list after receiving keys from successor")
        print_resource_list()

def givekey_parser(response):
    global node_predecessor, loc_rsc, resource_key
    part = response.split(' ')
    num_of_keys = int(part[2])
    if num_of_keys == 0:
        #print("No keys to be added to this node")
        # now sending ack to the precedessor
        print("Updated resource list after receiving keys from predecessor")
        print_resource_list()
        command = giveKeyOk()
        sending(node_predecessor[0], node_predecessor[1], command)

    else:
        print("Received keys from predecessor")
        for i in range(5, len(part), 2):
            # replacing "_" by a space in the string filename
            part[i] = part[i].replace("_", " ")
            file_name = part[i]
            file_hash = part[i + 1]
            file_hash_int = int(part[i + 1], 16)
            # converting to title case and then storing in keylist
            # part[i + 1] = part[i + 1].title()
            # temp[j] = part[i + 3]
            if part[i] not in resource_key:
                # loc_rsc.append(part[i])
                resource_key.append((file_name, file_hash, file_hash_int))
        print("Updated resource list after receiving keys from predecessor")
        print_resource_list()
        # now sending ack to the precedessor
        command = giveKeyOk()
        sending(node_predecessor[0], node_predecessor[1], command)
        # print("Enter Command: ")

def givekeyok_parser(response):
    global exit_ack, self_hash, network_nodes_list
    #temp_network_nodes_list = list()
    part = response.split(' ')
    print(part)
    if part[-1] == "0" and part[1] == "GIVEKYOK":
        print("GIVEKEY OK RESPONSE RECEIVED")
    #print("My keys are now sent to the successor")
    #print("Now I will update other nodes of my departure...")
    #Now update send update finger table (removal mode request to other nodes in the finger table)
#    temp_network_nodes_list = network_nodes_list[:]
#    my_list_entry = ((my_ip, my_port,self_hash, self_hash_int))
#    temp_network_nodes_list.append(my_list_entry)
#    #Now sorting the node list
#    temp_network_nodes_list.sort(key=lambda x: x[3])
#        #sending updates to other nodes:
#    send_updates_to = get_tobeupdated_nodes(temp_network_nodes_list)
    #create update finger table command for node removal:
    update_command = upfin(1, self_hash)
    for node in network_nodes_list:
        print("Sending update to " + str(node))
        sending(node[0],node[1], update_command)
#    for finger in finger_table:
#        sending(finger[0][0], int(finger[0][1]),command)
#        exit_ack = exit_ack + 1
#    #sending update to predecessor
#    print("sending update to predecessor")
#    sending(predecessor[0][0],int(predecessor[0][1]),command)
#    exit_ack = exit_ack + 1
    #once we get node removal update acknowledgement from the intended fingers,
    #this node will exit
    #so exit sequence is to be placed in the upfinok_parser()
    # issue unregister seqeunce
    C_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    C_sock.connect((BS_IPAddress, int(BS_port)))
    command = del_ip()
    # send node del command to BS
    C_sock.send(command)
    # receive response
    reg_ack = C_sock.recv(4096)
    C_sock.shutdown(socket.SHUT_RDWR)
    C_sock.close()
    # Pass it to a response processor
    response_processor(reg_ack, BS_address)

def exit_all_parser():
    global node_successor
    #print("This is the exit all parser")
    C_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    C_sock.connect((BS_IPAddress, int(BS_port)))
    command = del_ip()
    # send node del command to BS
    C_sock.send(command)
    # receive response
    # reg_ack = C_sock.recv(4096)
    # print("reg_ack: " ,reg_ack)
    C_sock.shutdown(socket.SHUT_RDWR)
    C_sock.close()
    os._exit(os.EX_OK)
    #send exit_all to node_successor
    #sending(node_successor[0], node_successor[1], )
    # Pass it to a response processor
    # response_processor(reg_ack, BS_address)

def search_parser(response):
   global resource_key, finger_table_master, node_successor, node_predecessor, self_hash_int
   #print("Search")
   # print_finger_table()
   byParts = response.split(" ")
   #print(byParts)
   key_to_find = byParts[-2]
   #create a list of keys:
   key_list = list()
   for resource in resource_key:
       key_list.append(resource[1])
   hops = int(byParts[-1])
   #print("Received hops", hops)
   adrs = (byParts[2], byParts[3])
   #whenever the search parser is called first check for the hops
   hops = hops - 1
   file_key_int = int(key_to_find,16)

   if key_to_find in key_list:
       # print("Found")
       found = [item for item in resource_key if key_to_find in item]
       # print found
       reply = serok(found, hops, 1)
       sending(adrs[0], int(adrs[1]), reply)
   else:
       if hops == 0:
           #print("do not fwd.. Send Not Found")
           reply = serok([key_to_find], hops, 0)
           sending(adrs[0], int(adrs[1]), reply)
           # this means do not forward just check locally and kill it
       elif node_predecessor[3] > self_hash_int:
           if node_predecessor[3] < file_key_int < 1048576 or 0 <= file_key_int < self_hash_int:
               #print("do not fwd.. Send Not Found")
               reply = serok([key_to_find], hops, 0)
               sending(adrs[0], int(adrs[1]), reply)
               # to check whether it is in range
           else:
               pass
       elif node_predecessor[3] < file_key_int < self_hash_int:
           #print("do not fwd.. Send Not Found")
           reply = serok([key_to_find], hops, 0)
           sending(adrs[0], int(adrs[1]), reply)
       else:
           #print("Forwarding the request")
           new_response = response[:-1] + str(hops)
           for finger in finger_table_master:
               if finger[1][0] > finger[1][1]:
                   #print("Range splitting:")
                   if finger[1][0] < file_key_int < 1048576 or 0 <= file_key_int < finger[1][1]:
                       sending(finger[3], finger[4], new_response)
                       break
               elif finger[1][0] < file_key_int < finger[1][1]:
                   sending(finger[3], finger[4], new_response)
                   break


#
#    else:
#        #fwd to other nodes
#        if key_to_find in key_list:
#            #print("Found")
#            found = [item for item in resource_key if key_to_find in item]
#            #print found
#            reply = serok(found,hops, 1)
#            sending(adrs[0], int(adrs[1]), reply)
# #        elif int(key_to_find,16) < self_hash_int:
# #                print("Send Not Found")
# #                # Need to build response for this
# #                reply = serok([key_to_find],hops, 0)
# #                sending(adrs[0], int(adrs[1]), reply)
#        else:
#            print("Finding the nearest node")
#            int_key = int(key_to_find, 16)
#            forward = None
#            new_response = response[:-1] + str(hops)
#            for entry in finger_table_master:
#                if int_key < entry[2]:
#                    #print("Forwardin to node")
#                    forward = entry
#                    #print(forward)
#                    sending(forward[3], forward[4],new_response)
#                    break
#            if forward == None:
#                if node_successor == network_nodes_list:
#                    forward = node_successor
#                    sending(forward[0], forward[1],new_response)
#                else:
#                    #print("Forwarding to last node")
#                    forward = finger_table_master[-1]
#                    sending(forward[3], forward[4],new_response)
##def user_search(response,src):

def user_search(response, mode):
   global node_successor, finger_table_master, network_nodes_list, node_predecessor, self_hash_int
   # mode 0 for user_input use and mode 1 for sending zipf generated values
   #print("User Search")
   # print_finger_table(finger_table_master)
    # create a list of keys:
   key_list = list()
   for resource in resource_key:
       key_list.append(resource[1])
   byParts = response.split(" ")
   if mode == 0:
       file_name = byParts[1]
       file_name = file_name.replace("_" , " ")
       file_hash = hashing(file_name,2)
       int_key = int(file_hash, 16)
       # print("File hash: ",file_hash)
   elif mode == 1:
       #print("Mode 1: ")
       file_hash = byParts[4]
       int_key = int(file_hash, 16)
       # print("File hash: ",file_hash)
   else:
       pass

   if file_hash in key_list:
       print("Found locally")
   elif node_predecessor[3] > self_hash_int:
       if node_predecessor[3] < int_key < 1048576 or 0 <= int_key < self_hash_int:
           print("Key is not present in network")
           # to check whether it is in range
       else:
           pass
   elif node_predecessor[3] < int_key < self_hash_int:
       print("Key is not present in network")
   else:
       command = ser(file_hash)
       print("Finding the nearest node")
       # int_key = int(file_hash, 16)
       #print("File hash:", file_hash)
       #print("File int: ",int_key)
       # forward = None
       # print("User search later finger_table_master", finger_table_master)

       # for finger in finger_table_master:
       #     if finger[1][0] < int_key < finger[1][1]:
       #         # Sending keys to respective finger
       #         sending(finger[3], int(finger[4]), command)
       #         print("Sent to:{}:{} ".format(finger[3], finger[4]))
       #         break

       for finger in finger_table_master:
           if finger[1][0] > finger[1][1]:
               #print("Range splitting:")
               if finger[1][0] < int_key < 1048576 or 0 <= int_key < finger[1][1]:
                   sending(finger[3], finger[4], command)
                   print("Sent to:{}:{} ".format(finger[3], finger[4]))
                   break
           elif finger[1][0] < int_key < finger[1][1]:
               sending(finger[3], finger[4], command)
               print("Sent to:{}:{} ".format(finger[3], finger[4]))
               break


                       # for entry in finger_table_master:
       #     if int_key < entry[2]:
       #         # print("Forwardin to node")
       #         forward = entry
       #         # print(forward)
       #         sending(forward[3], forward[4], command)
       #         break
       # if forward == None:
       #     if node_successor == network_nodes_list[0]:
       #         forward = node_successor
       #         # print("Forwading to successor")
       #         sending(forward[0], forward[1], command)
       #     else:
       #         # print("Forwarding to last node")
       #         forward = finger_table_master[-1]
       #         sending(forward[3], forward[4], command)




def searchOK_parser(response, recvd_from):
   global max_hops
   byParts = response.split(" ")
   recvd_hops = byParts[2]
   # print(byParts)
   if int(byParts[2]) == 0:
       print("Resource " + byParts[-1] + " not found at: "+ recvd_from[0] + " in " + str(max_hops - int(recvd_hops)) + " hops.")
   elif int(byParts[2]) == 1:
       print("Resource " + byParts[-1] + " found at: "+ recvd_from[0] + " in " + str(max_hops - int(recvd_hops)) + " hops.")

# Functions to support zipf mode
# ---------------------------------------------------------------------------------
def popularity_calculator(zipf_factor):
    global loc_rsc
    weighted_array = []
    #print("This is the popularity calculator function")
    # issuing del ip sequence:
    # summation:
    summ = 0
    for i in range(0,len(loc_rsc)):
        summ = summ +(1/((i+1)**(zipf_factor)))
    # print(summ)
    num = 0
    for i in range(0,len(loc_rsc)):
        num = (1/(i+1**zipf_factor))
        weighted_array.append(num/summ)
    return weighted_array

def generate_queries(rank_array,query_count):
    global all_resources
    # print("all_resources", all_resources)
    frequency_list = list()
    # creating a list containing frequency values for each query
    for i in range(0,len(rank_array)):
        a = rank_array[i]
        a = a*5000
        frequency_list.append(int(a))
    # print(frequency_list)
    # creating a list of queries using the calculating frequency vector
    query_list = list()
    for i in range(0,len(frequency_list)):
        for j in range(frequency_list[i]):
            query_list.append(all_resources[i])
    # generating random queries based on query count
    return random.sample(query_list, query_count)

def generate_query_parser(response):
    print('Generating queries based on zipf distribution')
    byParts = response.split(" ")
    zipf_factor = byParts[2]
    No_of_queries = byParts[3]
    query_file = byParts[4]
    fixed_queries = list()
    #print("Query file:"+ query_file)
    rank_array = popularity_calculator(float(zipf_factor))
    generated_queries = generate_queries(rank_array,int(No_of_queries))
    for line in generated_queries:
        fixed_queries.append(line.replace(" ", "_"))
    #DELETE generated_queries file if it exists
    try:
        os.remove(query_file)
    except OSError:
        pass
    #Writing generated queries to a file on the node.
    file = open(query_file,'w')
    for query in fixed_queries:
        file.write("%s" % query)
    file.close()
    print("Generated Queries are saved to " + query_file + " in the program directory")

def send_query_parser(response):
    #print("send query parser")
    byParts = response.split(" ")
    query_file = byParts[2]
    #check if file is not present, tell user to first generate the file
    if ( not os.path.exists(query_file)):
        print("Query File not found. Please generate a query file using GENERATE QUERY options")
    else:
        #print("read each query from the file and send it one by one")
        #reading entire file into an array
        queries = list()
        f = open(query_file ,'r')
        queries = f.readlines()
        f.close()
    #printing the queries in an array
    #print("printing contents in an array", queries)
    #sending request for each element of the array sequentially
    for i in range(0,len(queries)):
        temp = queries[i].rstrip("\n")
        temp = temp.rstrip("\r")
        temp = temp.replace("_"," ")
        # print("printing temp",temp)
        search_for_key = hashing(temp,2)
        # print("search_for_key", search_for_key)
        response = ser(search_for_key)
        #print("search message", response)
        user_search(response, 1)

# ----------------------------------------------------------------------------------------
def response_processor(response, src_node):
    global finger_table_master
    """ This function is used for processing response messages.
        Possible message responses are as follows:
        GOOD RESPONSES:
        REGOK, DEL IPADDRESS OK, DEL UNAME OK, JOINOK, LEAVEOK, SEROK
        BAD RESPONSES:
        BS REQ, REG OK <username> -1, REG OK 9999, REG OK 9998
        DEL IPADDRESS OK -1, DEL UNAME OK -1, DEL OK -1
        DEL IPADDRESS OK 9998, DEL UNAME OK 9999
        All the bad responses are handled in error_code_description function
        print("received response: ", response)
    """
    #debug
    print("\nReceived response from ip: {} port: {}".format(src_node[0],src_node[1]))
    print(response)
    # check errors
    if error_code_description(response) == 0:
        # Process response (get ips and port numbers based on no_nodes, form/update routing table)
        # checking and parsing for REG OK
        if "REGOK" in response:
            reg_parser(response)
        elif "UPFINOK" in response:
            upfinok_parser(response)
        elif "UPFIN" in response:
            upfin_parser(response)
        elif "GETKYOK" in response:
            getkeyok_parser(response)
        elif "GETKY" in response:
            getkey_parser(response)
        elif "GIVEKYOK" in response:
            givekeyok_parser(response)
        elif "GIVEKY" in response:
            givekey_parser(response)
        elif "NETWORK NODE LIST" in response:
            print_node_list()
        elif "SEROK" in response:
            searchOK_parser(response, src_node)
        elif "SER" in response:
            search_parser(response)
        elif "DEL IPADDRESS" in response or "DEL UNAME" in response:
            del_parser(response)
        elif "ADDOK" in response:
            addok_parser(response)
        elif "ADD" in response:
            add_parser(response)
        elif "GET RESOURCE LIST" in response:
            print_resource_list()
        elif "DETAILS" in response:
            # Display the nodeIP, PORT and KEY
            print("Node IP " + my_ip + " " + "Port " + str(my_port) + " Node-Hash " + self_hash + " " + str(self_hash_int))
        elif "FINGERTABLE" in response:
            # fingertable: Display the node finger table.
            print("Finger Table:")
            print_finger_table(finger_table_master)
        elif "KEYTABLE" in response:
#            # keytable: Display the node key table.return succ_decimal, prede_decimal
            print("Keytable:")
            print("self_hash",self_hash)
            print(resource_key)
        elif "SEARCH" in response:
            # search: To execute search.
            user_search(response, 0)
        elif "GENERATE QUERY" in response:
            # Generate query file using zipf distribution
            generate_query_parser(response)
        elif "SEND QUERY" in response:
            # Send queries sequentially by reading the query file
            send_query_parser(response)
        elif "EXIT ALL" in response:
            # Send queries sequentially by reading the query file
            exit_all_parser()
        elif "HELP":
            # search: To execute search.
            usage()
        else:
            # what is this??
            print("INVALID INPUT")
            # printing help usage
            usage()
#########################################################
################ Main Code entry point ###################
if __name__ == "__main__":
    # node identification
    self_hash = hashing(laddress, 1)
    self_hash_int = int(self_hash,16)
    my_self = (my_ip,my_port,self_hash,self_hash_int)
    # Import resources.txt and choose random file namesmy_self
    loc_rsc = importing()
    for i in range(0, len(loc_rsc)):
        resource_name = loc_rsc[i]
        resource_hash = hashing(loc_rsc[i], 2)
        resource_hash_int = int(resource_hash, 16)
        tuple = (resource_name, resource_hash, resource_hash_int)
        resource_key.append(tuple)
        i = i + 1
    print_resource_list()
    #print("resource_key", resource_key)
    #begin writing to log file
    print("LOG created")
    logging.info('LOG FILE CREATED')
    #write to log
    logging.info('[INFO] '+ 'Node initialized')
    try:
        # Creating the server Socket        
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(laddress)
        server_socket.listen(5)
        # initiating registeration process:
        # ---------------------
        # Connect the socket to the port where the server is listening
        #print("debug")
        C_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        C_sock.connect((BS_IPAddress, int(BS_port)))
        # send node registeration command to BS
        reg_req = reg()
        C_sock.send(reg_req)
        # receive response
        reg_ack = C_sock.recv(4096)
        #logging reg_ack
        logging.info('[INFO] '+ reg_ack)
        # print("reg_ack: " ,reg_ack)
        C_sock.shutdown(socket.SHUT_RDWR)
        C_sock.close()
        # Pass it to a response processor
        response_processor(reg_ack, laddress)
        # User Input:
        thread1 = threading.Thread(target=user_in)
        thread1.start()
        #This loop services network messages
        while 1:
            #print("continuous receive mode: ")
            client_socket, addr = server_socket.accept()
            client_input = client_socket.recv(2048)
            #print("Input from other node: " ,client_input)
            #logging client_input
            logging.info('[INPUT] '+ client_input)
            msg_to_send = response_processor(client_input, addr)
            # print("Msg to send: " ,msg_to_send)
            if msg_to_send == None:
                pass
            else:
                server = Server(client_socket, msg_to_send, addr)
                server.start()
    except socket.error as message:
        print("Error Code: ", str(message[0]), "  ", str(message[1]))