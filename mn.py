#!/usr/bin/python2

import six
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.node import RemoteController, OVSSwitch

if __name__ == '__main__':

    net = Mininet(switch=OVSSwitch)
    net.addController('c0',controller=RemoteController)

    s1 = net.addSwitch('s1')
    host = {'h1':'10.0.0.1',
            'h2':'10.0.0.2',
            'h3':'10.0.0.3',
            }
    for h, ip in host:
        net.addLink(s1,net.addHost(h, ip))

    net.build()
    net.start()
    command = 'ovs-vsctl set Bridge %s protocols=%s' % (s1, ['OpenFlow13'])
    switch.cmd(command.split(' '))