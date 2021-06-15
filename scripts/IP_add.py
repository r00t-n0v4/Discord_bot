import socket
def get_Host_name_IP():
    try:
        host_name: socket.gethostname()
        host_ip = socket.gethostbyname(host_name)
        print("Host name is: ", host_name)
        print("Ip address is: ", host_ip)
    except:
        print("Unable to get Hostname and IP")        
    
    
    get_Host_name_IP()