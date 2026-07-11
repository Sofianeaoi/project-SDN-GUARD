#!/usr/bin/env python3



#function to ping between 2 hosts 

def generate_icmp(net):
    
    print("Choose the source host for pinging:")
    src_name = input("Enter the source host: ")
    while src_name not in ['h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'h7', 'h8', 'h9']:
        print("Invalid source host. Please choose from h1, h2, h3, h4, h5, h6, h7, h8, h9.")
        src_name = input("Enter the source host: ")
        
    src = net.get(src_name)
    
    print("Choose the destination host for pinging:")
    dst_name = input("Enter the destination host (h1, h2, h3, h4, h5, h6, h7, h8, h9): ")
    while dst_name not in ['h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'h7', 'h8', 'h9'] or dst_name == src_name:
        print("Invalid destination host. Please choose from h1, h2, h3, h4, h5, h6, h7, h8, h9.")
        dst_name = input("Enter the destination host: ")
    dst = net.get(dst_name)

    ping = src.cmd('ping -c 3   %s' %dst.IP())
    print(ping)
    

    if '0% packet loss' in ping:
        print("ping successful")
        return True
    else:
        print("ping failed")
        return False
    #i redifined the function to ping and choosing the hosts only when it is called in the main
    
    
    
    
#this functions aims to generate http traffic considering h2 as a server   

def generate_http(net): 
    
