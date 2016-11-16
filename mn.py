#!/usr/bin/python2

from mininet.net import Mininet
from mininet.cli import CLI
from mininet.node import RemoteController

if __name__ == '__main__':

    net = Mininet()

    net.addController('c0',controller=RemoteController)
    s1 = net.addSwitch('s1')
    host = {'h1':'10.0.0.1',
            'h2':'10.0.0.2',
            'h3':'10.0.0.3',
            }
    for h, ip in host:
        addlink(net.addHost(h, ip), s1)
    net.start()
    ofp_version(s1, ['OpenFlow13'])