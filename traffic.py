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

def generate_http_traffic(net):

    print("Choose the source host:")
    src_name = input("Source host: ")

    while src_name not in ['h1','h3','h4','h5','h6','h7','h8','h9']:

        if src_name == "h2":
            print("h2 is the HTTP server.")
        else:
            print("Invalid host.")

        src_name = input("Source host: ")

    src = net.get(src_name)
    dst = net.get("h2")

    methods = {
        "GET":    f"curl -i -X GET http://{dst.IP()}:8080",
        "POST":   f"curl -i -X POST -d 'username=sofiane' http://{dst.IP()}:8080",
        "PUT":    f"curl -i -X PUT -d 'new_data' http://{dst.IP()}:8080",
        "PATCH":  f"curl -i -X PATCH -d 'field=value' http://{dst.IP()}:8080",
        "DELETE": f"curl -i -X DELETE http://{dst.IP()}:8080",
      
    }

    while True:
        print("\n Enter a choice of HTTP method to send to the server (h2) (GET,POST,PUT,PATCH,DELETE)or type 'exit' to quit")
        method = input("Method: ").upper()#converting in uppercase 

        if method == "EXIT":
            break

        if method not in methods:
            print("Invalid method.")
            continue

        response = src.cmd(methods[method])
        if "200 OK" in response:
            print("Request successful")
        else:
            print("Request failed")

        
        print(response)
        
        

