#this file will be used to generate attacks in the network  
import random

def icmp_flood(net):
        src_list= ['h1','h2','h3','h4','h5','h6','h7','h8','h9']
        src_name=random.choice(src_list)
        
        src = net.get(src_name)
        
        dst_name=None
        while dst_name not in ['h1','h2','h3','h4','h5','h6','h7','h8','h9'] or dst_name == src_name:
            
            dst_name = random.choice(src_list)
        dst = net.get(dst_name)
        
        src.cmd(f'ping -c 500 -i 0.0001 {dst.IP()} &') #lanching a ping request every 1ms in background 
        
def SYN_flood(net):
    

        
        