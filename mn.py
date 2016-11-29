#!/usr/bin/python2

from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSController
from mininet.node import CPULimitedHost, Host, Node
from mininet.node import OVSKernelSwitch, UserSwitch
from mininet.node import IVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink, Intf
from subprocess import call

def myNetwork():

    net = Mininet( topo=None,
                   build=False,
                   ipBase='192.168.0.0/16')

    info( '*** Adding controller\n' )
    c0=net.addController(name='c0',
                      controller=RemoteController,
                      ip='127.0.0.1',
                      protocol='tcp',
                      port=6633)

    info( '*** Add switches\n')
    s1 = net.addSwitch('s1', cls=OVSKernelSwitch, dpid='1', protocols='OpenFlow13')
    s2 = net.addSwitch('s2', cls=OVSKernelSwitch, dpid='2', protocols='OpenFlow13')

    info( '*** Add hosts\n')
    h1 = net.addHost('h1', cls=Host, ip='192.168.1.1/24', defaultRoute='192.168.1.254')
    h2 = net.addHost('h2', cls=Host, ip='192.168.1.2/24', defaultRoute='192.168.1.254/24')
    h3 = net.addHost('h3', cls=Host, ip='192.168.1.3/24', defaultRoute=None)
    
    h4 = net.addHost('h4', cls=Host, ip='192.168.1.4/24', defaultRoute=None)
    h5 = net.addHost('h5', cls=Host, ip='192.168.1.5/24', defaultRoute=None)
    h6 = net.addHost('h6', cls=Host, ip='192.168.1.6/24', defaultRoute=None)

    info( '*** Add links\n')
    net.addLink(s2, h4)
    net.addLink(s2, h5)
    net.addLink(s2, h6)

    net.addLink(s2, s1)

    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s1)

    info( '*** Starting network\n')
    net.build()
    info( '*** Starting controllers\n')
    for controller in net.controllers:
        controller.start()

    info( '*** Starting switches\n')
    net.get('s1').start([c0])
    net.get('s2').start([c0])

    info( '*** Post configure switches and hosts\n')

    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    myNetwork()
