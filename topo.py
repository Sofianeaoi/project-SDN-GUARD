#!/usr/bin/env python3

from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel


def myNetwork():

    net = Mininet(
        topo=None,
        build=False,
        ipBase='192.168.2.0/24'
    )

    # Controller
    c0 = net.addController(
        'c0',
        controller=RemoteController,
        ip='192.168.1.2',      #the ip address of the 2nd vm to link it whit ryu 
        port=6653
    )

    #creation of the switches 
    s1 = net.addSwitch('s1')
    s2 = net.addSwitch('s2')
    s3 = net.addSwitch('s3')

    #creation of the hosts
    h1 = net.addHost('h1', ip='192.168.2.1/24')
    h2 = net.addHost('h2', ip='192.168.2.2/24')
    h3 = net.addHost('h3', ip='192.168.2.3/24')

    h4 = net.addHost('h4', ip='192.168.2.4/24')
    h5 = net.addHost('h5', ip='192.168.2.5/24')
    h6 = net.addHost('h6', ip='192.168.2.6/24')

    h7 = net.addHost('h7', ip='192.168.2.7/24')
    h8 = net.addHost('h8', ip='192.168.2.8/24')
    h9 = net.addHost('h9', ip='192.168.2.9/24')

    # links between switches 
    net.addLink(s1, s2)
    net.addLink(s2, s3)

    # Hosts and their links with switches 
    net.addLink(s1, h1)
    net.addLink(s1, h2)
    net.addLink(s1, h3)

    net.addLink(s2, h4)
    net.addLink(s2, h5)
    net.addLink(s2, h6)

    net.addLink(s3, h7)
    net.addLink(s3, h8)
    net.addLink(s3, h9)

    
    net.build()


    c0.start()


    s1.start([c0])
    s2.start([c0])
    s3.start([c0])



    print("H1 IP:", h1.IP()) #testing if the ip config has been done 

    CLI(net)

    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    myNetwork()
    