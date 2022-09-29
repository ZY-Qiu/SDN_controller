from operator import truediv
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp
from ryu.lib.packet import icmp
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import ipv4
from ryu.lib.packet import ipv6
from ryu.topology import event
from ryu.topology.api import get_switch, get_link
from ryu.ofproto import inet
import matplotlib.pyplot as plt
from networkx.drawing.nx_pylab import draw_networkx
import time

import networkx as nx

ARP = arp.arp.__name__
ICMP = icmp.icmp.__name__
TCP = tcp.tcp.__name__
UDP = udp.udp.__name__
IPv4 = ipv4.ipv4.__name__
IPv6 = ipv6.ipv6.__name__

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        # arp table and table for every arp entry
        self.arp_table = {}
        self.reentry = {}
        # topology
        self.topology_api_app = self
        self.network = nx.DiGraph()
        self.paths = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        print("install table-miss flow entry")
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(event.EventSwitchEnter,[CONFIG_DISPATCHER,MAIN_DISPATCHER])
    def _get_topology(self, ev):
        print("get topology")
        switch_list = get_switch(self.topology_api_app, None)
        switches = [switch.dp.id for switch in switch_list]
        self.network.add_nodes_from(switches)

        #store links info
        link_list = get_link(self.topology_api_app, None)
        #need src,dst,weigtht
        links = [(link.src.dpid,link.dst.dpid,{'port':link.src.port_no}) for link in link_list]
        self.network.add_edges_from(links)
        #bidirectional, turn port src to dst, warning
        links  = [(link.dst.dpid,link.src.dpid,{'port': link.dst.port_no}) for link in link_list]
        self.network.add_edges_from(links)

    def _shortest_path(self, header_list, datapath, src, dst, in_port):
        print("finding shortest path")
        dpid = datapath.id #siwtch id
        #add the host to the network
        self.paths.setdefault(dpid, {})
        if src not in self.network:
            print("add src to the network ")
            self.network.add_node(src)
            self.network.add_edge(dpid, src, port=in_port)
            self.network.add_edge(src, dpid)
            #path is like: {src1:{dst1:[],dst2:[],dst3:[]....},src2:{dst1:[],dst2:[],dst3:[]....},}
            self.paths.setdefault(src, {})

        if dst == "ff:ff:ff:ff:ff:ff":
            print("broadcast msg: flood")
            return datapath.ofproto.OFPP_FLOOD

        if dst in self.network:
            #draw_networkx(self.network)
            #plt.show()
            #time.sleep(5)
            #plt.close()
            print("dst: {} Found in the network".format(dst))
            if dst not in self.paths[src]:
                print("compute shortest path using dijkstra")
                #dijkstra
                paths = [path for path in nx.all_shortest_paths(self.network, dpid, dst)]
                if len(paths) == 1:
                    print("only one shortest path found")
                    self.paths[dpid][dst] = paths[0]
                else:
                    print("multiple shortest path found")
                    if ICMP in header_list or TCP in header_list:
                        print("TCP/ICMP: take clockwise path")
                        #clockwise path
                        for path in paths:
                            if (path[1] % 4) + 1 == path[2]:
                                self.paths[dpid][dst] = path
                    elif UDP in header_list:
                        print("UDP: take counter clockwise path")
                        #counter clockwise path
                        for path in paths:
                            if path[1] == (path[2] % 4) + 1:
                                self.paths[dpid][dst] = path
                    else:
                        print("choose the path randomly")
                        self.paths[dpid][dst] = paths[0]
            # path is a list of nodes from src to dst
            path = self.paths[dpid][dst]
            print("path: {}".format(path))
            next_hop = path[1]
            out_port = self.network[dpid][next_hop]['port']
            print("next_hop is {}, out_port is {}".format(next_hop, out_port))
        else:
            out_port = datapath.ofproto.OFPP_FLOOD
            #print("dst Not found: flood")
        return out_port


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        match_flag = False

        pkt = packet.Packet(msg.data)

        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        
        
        dst = eth.dst
        src = eth.src
        
        dpid = datapath.id

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        header_list = dict((p.protocol_name, p)for p in pkt.protocols if type(p) != str)
        
        if IPv6 in header_list:
            return
        
        print("packet_in")
        #print(header_list)

        if ARP in header_list:
            #print("ARP learning")
            self.arp_table[header_list[ARP].src_ip] = src
            if self._arp_handler(pkt, datapath, in_port):
                # if true arp handler done reply or drop, else pass.
                return
            match_flag = True
            # ethertype of ARP is 0x0806
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src, eth_type=eth.ethertype)

        if TCP in header_list:
            print("[TCP] arrive at ", datapath.id, header_list[IPv4].dst)
            if header_list[TCP].dst_port == 80 and (header_list[IPv4].src == "10.0.0.2" or header_list[IPv4].src == "10.0.0.4"):
                print("h2 and h4 cannot send HTTP packet")
                #flowmod the switch to send HTTP msg from this host to the controller
                if header_list[IPv4].src == "10.0.0.2":
                    match = parser.OFPMatch(eth_type = eth.ethertype, ip_proto=inet.IPPROTO_TCP, tcp_dst=80, ipv4_src="10.0.0.2")
                elif header_list[IPv4].src == "10.0.0.4":
                    match = parser.OFPMatch(eth_type = eth.ethertype, ip_proto=inet.IPPROTO_TCP, tcp_dst=80, ipv4_src="10.0.0.4")
                actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
                # have higher priority
                self.add_flow(datapath, 5, match, actions, msg.buffer_id)
                # create a RST pkt and send it back to the sender host
                tcp_rst = packet.Packet()
                tcp_rst.add_protocol(ethernet.ethernet(ethertype=eth.ethertype, src=dst, dst=src))
                tcp_rst.add_protocol(ipv4.ipv4(src=header_list[IPv4].dst, dst=header_list[IPv4].src, proto=6))
                tcp_rst.add_protocol(tcp.tcp(src_port=header_list[TCP].dst_port, 
                    dst_port=header_list[TCP].src_port, ack=header_list[TCP].seq+1, bits=0b010100))
                tcp_rst.serialize()
                action = [parser.OFPActionOutput(in_port)]
                out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                    in_port=datapath.ofproto.OFPP_CONTROLLER, actions=action, data=tcp_rst.data)
                datapath.send_msg(out)
                print("TCP rejected on S{}".format(dpid))
                return
            else:
                match_flag = True
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src, eth_type=eth.ethertype, ip_proto=inet.IPPROTO_TCP, tcp_dst=header_list[TCP].dst_port)

        if UDP in header_list:
            print("[UDP] arrive at ", datapath.id, header_list[IPv4].dst)
            if (header_list[IPv4].src == "10.0.0.1" or header_list[IPv4].src == "10.0.0.4"):
                print("h1 and h4 cannot send UDP packet, drop")
                #flowmod the switch
                if header_list[IPv4].src == "10.0.0.1": 
                    match = parser.OFPMatch(eth_type = eth.ethertype, ip_proto=inet.IPPROTO_UDP, ipv4_src="10.0.0.1")
                elif header_list[IPv4].src == "10.0.0.4":
                    match = parser.OFPMatch(eth_type = eth.ethertype, ip_proto=inet.IPPROTO_UDP, ipv4_src="10.0.0.4")
                inst = [parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS, [])]
                if msg.buffer_id:
                    mod = parser.OFPFlowMod(datapath=datapath, buffer_id=msg.buffer_id,
                                            priority=5, match=match,
                                            instructions=inst)
                else:
                    mod = parser.OFPFlowMod(datapath=datapath, priority=5,
                                            match=match, instructions=inst)
                datapath.send_msg(mod)
                return
            else:
                match_flag = True
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src, eth_type=eth.ethertype, ip_proto=inet.IPPROTO_UDP)

        if ICMP in header_list:
            print("[ICMP] arrive at ", datapath.id, header_list[IPv4].dst)
            match_flag = True
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src, eth_type=eth.ethertype, ip_proto=inet.IPPROTO_ICMP)

        out_port = self._shortest_path(header_list, datapath, src, dst, in_port)
        if out_port == -1:
            return

        actions = [parser.OFPActionOutput(out_port)]
        
        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            if not match_flag:
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def _deloop(self, datapath, eth_src, ip_dst, in_port):
        print("broadcast msg de-loop")
        if (datapath.id, eth_src, ip_dst) in self.reentry:
            if self.reentry[(datapath.id, eth_src, ip_dst)] != in_port:
                # another port with the same tuple
                out = datapath.ofproto_parser.OFPPacketOut(
                    datapath=datapath,
                    buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                    in_port=in_port,
                    actions=[], data=None)
                datapath.send_msg(out)
            return True
        else:
            self.reentry[(datapath.id, eth_src, ip_dst)] = in_port
            return False

    def _arp_handler(self, pkt, datapath, in_port):
        pkt_arp = pkt.get_protocol(arp.arp)
        pkt_eth = pkt.get_protocol(ethernet.ethernet)
        ip_dst = pkt_arp.dst_ip
        eth_dst = pkt_arp.dst_mac
        ip_src = pkt_arp.src_ip
        eth_src = pkt_arp.src_mac
        action = []

        if pkt_arp.opcode == arp.ARP_REQUEST:
            print("[ARP] request arrive at ", datapath.id, ip_dst)
            # must break the loop for broadcast msg
            if self._deloop(datapath, eth_src, ip_dst, in_port):
                print("ARP broadcast re-enter: drop")
                return True
            if ip_dst in self.arp_table:
                print("Hit in arp table")
                action.append(datapath.ofproto_parser.OFPActionOutput(in_port))
                arp_reply = packet.Packet()
                arp_reply.add_protocol(ethernet.ethernet(ethertype=pkt_eth.ethertype, 
                    src=self.arp_table[ip_dst], dst=eth_src))
                arp_reply.add_protocol(arp.arp(opcode=arp.ARP_REPLY, src_mac=self.arp_table[ip_dst], 
                    src_ip=ip_dst, dst_mac=eth_src, dst_ip=ip_src))
                arp_reply.serialize()
                out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                    in_port=datapath.ofproto.OFPP_CONTROLLER, actions=action, data=arp_reply.data)
                datapath.send_msg(out)
                return True
            else:
                print("Miss in arp table")
        else:
            print("[ARP] reply arrive at ", datapath.id, ip_dst)
            # for dst ip not in arp table or an arp reply, ignore and let the main handler do the rest
            pass

        return False