#!/usr/bin/python2

import six
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.link import Link
from mininet.node import RemoteController, OVSSwitch
from mininet.topo import Topo



if __name__ == '__main__':
    s1 = net.addSwitch('s1')
    c0 = net.addController( 'c0', controller=RemoteController)
    net = Mininet()             
    host = {
        'h1':'10.0.0.1',
        'h2':'10.0.0.2',
        'h3':'10.0.0.3',
        }
    for h, ip in host:
        _host = net.addHost(h)
        _host.setIP(ip, 24)
        net.addLink(s1, h)
    net.start()
    
    command = 'ovs-vsctl set Bridge %s protocols=%s' % (s1, ['OpenFlow13'])
    print(s1.cmd(command.split(' ')))
    
    CLI( net )                                                                                                            
    net.stop()  
    