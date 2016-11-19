#!/usr/bin/python2

import six
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.link import Link
from mininet.node import RemoteController, OVSSwitch
from mininet.topo import Topo



if __name__ == '__main__':
    topo = Topo()
    s1 = topo.addSwitch('s1')
    host = {'h1':'10.0.0.1',
            'h2':'10.0.0.2',
            'h3':'10.0.0.3',
            }
    for h, ip in host:
        _host = topo.addHost(h,{'setIp':ip})
        topo.addLink(s1, _host)
    net = Mininet(switch=OVSSwitch, topo=topo)
        
    net.addController('c0',controller=RemoteController)
    net.build()
    net.start()
    command = 'ovs-vsctl set Bridge %s protocols=%s' % (s1, ['OpenFlow13'])
    switch.cmd(command.split(' '))