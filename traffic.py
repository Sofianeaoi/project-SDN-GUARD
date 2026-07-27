#!/usr/bin/env python3
import time 
import random
# i am using interactive mode to generate traffic but once all the traffic will be done i will use a random generator to generate traffic  for the creation of the dataset 


#function to ping between 2 hosts 

def generate_icmp(net):
    
    hosts=['h1','h2','h3','h4','h5','h6','h7','h8','h9']
    src_name=random.choice(hosts)

    src = net.get(src_name)
    dst_name=None
    while dst_name not in hosts or dst_name==src_name:
        dst_name=random.choice(hosts)
    
    dst=net.get(dst_name)

    ping = src.cmd('ping -c 3   %s' %dst.IP())
    

    if '0% packet loss' in ping:
        
        return True
    else:
        
        return False
    #i redifined the function to ping and choosing the hosts only when it is called in the main
    
    
    
    
#this functions aims to generate http traffic considering h2 as a server   

def generate_http_traffic(net):

    
    list_http=['h1','h3','h4','h5','h6','h7','h8','h9']
    src_name=None
    

    while src_name not in list_http:
        src_name=random.choice(list_http)

    src = net.get(src_name)
    dst = net.get("h2")

    methods = {
        "GET":    f"curl -i -X GET http://{dst.IP()}:8080",
        "POST":   f"curl -i -X POST -d 'username=sofiane' http://{dst.IP()}:8080",
        "PUT":    f"curl -i -X PUT -d 'new_data' http://{dst.IP()}:8080",
        "PATCH":  f"curl -i -X PATCH -d 'field=value' http://{dst.IP()}:8080",
        "DELETE": f"curl -i -X DELETE http://{dst.IP()}:8080",
      
    }

    method = random.choice(list(methods.keys())) #choosing a random http requete 
    response = src.cmd(methods[method])

        
        
        
        
def generate_ssh(net):
    src_list= ['h1','h2','h3','h4','h5','h6','h7','h8','h9']
    src_name= random.choice(src_list)

    src = net.get(src_name)
    
    dst_name=None
    while dst_name not in src_list or dst_name == src_name:
        
        dst_name = random.choice(src_list)
    dst = net.get(dst_name)
    
    src.cmd(f'ssh {dst.IP()}')
    
    
    
def generate_TCP(net):
    src_list= ['h1','h2','h3','h4','h5','h6','h7','h8','h9']
    src_name=random.choice(src_list)
    src = net.get(src_name)

    dst_name=None
    while dst_name not in src_list or dst_name == src_name:
        dst_name=random.choice(src_list)
        
    dst = net.get(dst_name)
    
    # Establish a TCP connection using iperf 
    src.cmd(f'iperf -c {dst.IP()} -p 6500')  #starting the connection 



def generate_UDP(net):
    src_list= ['h1','h2','h3','h4','h5','h6','h7','h8','h9']
    src_name=random.choice(src_list)
    
    src = net.get(src_name)
    
    dst_name=None
    while dst_name not in ['h1','h2','h3','h4','h5','h6','h7','h8','h9'] or dst_name == src_name:
        
        dst_name = random.choice(src_list)
    dst = net.get(dst_name)
    
    
    
    src.cmd(f'iperf -c {dst.IP()} -u -p 9900') 
    #the choice of the port was random
    
def generate_DNS(net):
    src_list=['h1','h2','h3','h4','h5','h7','h8','h9']
    src_name = random.choice(src_list)

    
    src = net.get(src_name)
    
    dst_name="h6"
    dst = net.get(dst_name)
    
    dns_data= "example.com"  #the data that will be sent to the server for the resolution
    command=src.cmd(f'dig @{dst.IP()} -p 2026 {dns_data}')  #the command to send the data to the server for the resolution and the server will be considered as a DNS server
    
    print(command)
    
    
    
def generate_traffic(net):
    TRAFFIC_LIST=[generate_icmp,generate_ssh,generate_TCP,generate_UDP,generate_http_traffic]
    
    session=500 # 500 protocoles will be generated 
    while session>0:
        time.sleep(1)
        protocole_chosen=random.choice(TRAFFIC_LIST)
        protocole_chosen(net)
        session -=1
        
        
#since i had probleme with DNS PROTOCOLE i decided to remove it from the traffic and keeping the script of the protocole there and the dns_server file their 
#i will probably fix the problem and find an easier issue to integrate a dns traffic in my topology 