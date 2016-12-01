#!/usr/bin/python2

from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSController
from mininet.node import CPULimitedHost, Host, Node
from mininet.node import OVSKernelSwitch, UserSwitch
from mininet.node import IVSSwitch
from mininet.node import Node
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink, Intf
from subprocess import call
from mininet.topo import Topo
from mininet.log import setLogLevel, info
from mininet.cli import CLI

class LinuxRouter( Node ):
    "A Node with IP forwarding enabled."

    def config( self, **params ):
        super( LinuxRouter, self).config( **params )
        # Enable forwarding on the router
        self.cmd( 'sysctl net.ipv4.ip_forward=1' )

    def terminate( self ):
        self.cmd( 'sysctl net.ipv4.ip_forward=0' )
        super( LinuxRouter, self ).terminate()
class NetworkTopo(Topo ):

 def build( self, **_opts ):
    info( '*** Add router\n')
    defaultIP = '192.168.3.254/24'  # IP address for r0-eth1
    router = self.addNode( 'r0', cls=LinuxRouter, ip=defaultIP )
    info( '*** Add switches\n')
    s1 = self.addSwitch('s1', cls=OVSKernelSwitch, dpid='1', protocols='OpenFlow13')
    s2 = self.addSwitch('s2', cls=OVSKernelSwitch, dpid='2', protocols='OpenFlow13')

    info( '*** Add hosts\n')
    h1 = self.addHost('h1', cls=Host, ip='192.168.3.1/24', defaultRoute='via 192.168.3.254')
    h2 = self.addHost('h2', cls=Host, ip='192.168.3.2/24', defaultRoute='via 192.168.3.254')
    h3 = self.addHost('h3', cls=Host, ip='192.168.3.3/24', defaultRoute='via 192.168.3.254')
    
    h4 = self.addHost('h4', cls=Host, ip='192.168.4.4/24', defaultRoute='via 192.168.4.254')
    h5 = self.addHost('h5', cls=Host, ip='192.168.4.5/24', defaultRoute='via 192.168.4.254')
    h6 = self.addHost('h6', cls=Host, ip='192.168.4.6/24', defaultRoute='via 192.168.4.254')

    info( '*** Add links\n')
    self.addLink( s1, router, intfName2='r0-eth1',
                params2={ 'ip' : defaultIP } )  # for clarity
    self.addLink( s2, router, intfName2='r0-eth2',
                params2={ 'ip' : '192.168.4.254/24' } )
    self.addLink(h1, s1)
    self.addLink(h2, s1)
    self.addLink(h3, s1)
    self.addLink(s2, h4)
    self.addLink(s2, h5)
    self.addLink(s2, h6)


def run():
    "Test linux router"
    topo = NetworkTopo()
    c = Controller(name='c0',
                      controller=RemoteController,
                      ip='127.0.0.1',
                      protocol='tcp',
                      port=6633)
    net = Mininet( topo=topo , controller=c)  # controller is used by s1-s3
    info( '*** Adding controller\n' )
    """c0= net.addController(name='c0',
                      controller=RemoteController,
                      ip='127.0.0.1',
                      protocol='tcp',
                      port=6633)
    """
    info( '*** Starting network\n')
    
    info( '*** Starting controllers\n')
    for controller in net.controllers:
        controller.start()

    info( '*** Starting switches\n')
    net.get('s1').start([c0])
    net.get('s2').start([c0])

    net.start()
    info( '*** Routing Table on Router:\n' )
    info( net[ 'r0' ].cmd( 'route' ) )
    CLI( net )
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    run()