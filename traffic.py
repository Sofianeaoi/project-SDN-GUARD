#!/usr/bin/env python3



#function to ping between 2 hosts 

def generate_icmp( src, dst):
    ping = src.cmd('ping -c 4 %s' % dst.IP()) 
    if '0% packet loss' in ping:
        print("ping successful")
        return True
    else:
        print("ping failed")
        return False
    
    
    
