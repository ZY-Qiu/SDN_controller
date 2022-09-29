#!/usr/bin/python

"""
This setup the topology in lab4
"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Controller, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.util import dumpNodeConnections
from mininet.link import Link, Intf, TCLink
import os 
from time import sleep
import sys

class Topology(Topo):
    
    
    def __init__(self):
        "Create Topology."
        
        # Initialize topology
        Topo.__init__(self)
        
      
        # Add hosts
        host1 = self.addHost('h1', ip='10.0.0.1/24', mac='10:00:00:00:00:01')
        host2 = self.addHost('h2', ip='10.0.0.2/24', mac='10:00:00:00:00:02')
        host3 = self.addHost('h3', ip='10.0.0.3/24', mac='10:00:00:00:00:03')
        host4 = self.addHost('h4', ip='10.0.0.4/24', mac='10:00:00:00:00:04')
        
        
        # Add switches
        sw1 = self.addSwitch('s1')
        sw2 = self.addSwitch('s2')
        sw3 = self.addSwitch('s3')
        sw4 = self.addSwitch('s4')
        
        self.addLink(host1, sw1, 1, 1)
        self.addLink(host2, sw2, 1, 1)
        self.addLink(host3, sw3, 1, 1)
        self.addLink(host4, sw4, 1, 1)
        
        self.addLink(sw1, sw2, 2, 3)
        self.addLink(sw2, sw3, 2, 3)
        self.addLink(sw3, sw4, 2, 3)
        self.addLink(sw4, sw1, 2, 3)

        

# This is for "mn --custom"
topos = { 'mytopo': ( lambda: Topology() ) }

