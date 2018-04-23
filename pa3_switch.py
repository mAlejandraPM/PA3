# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.ofproto import ether
from ryu.lib.packet import arp

robin_value = 1

class PA3Switch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    

    def __init__(self, *args, **kwargs):
        super(PA3Switch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
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
        print('sending flow message')   
        datapath.send_msg(mod)


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        print(' ')
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msgd.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        # learn a mac address to avoid FLOOD next time.
        # adds the mac address to port mapping
        self.mac_to_port[dpid][src] = in_port


        prots = pkt.get_protocols(ethernet.ethernet)
        for p in prots: 
            if p.ethertype == ether_types.ETH_TYPE_ARP:
                print('ARP packet here!')
                arp_packet = pkt.get_protocols(arp.arp)[0]
                if robin_value%2 ==  1:

                    #install flow for traffic to h5	
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, in_port=in_port, ipv4_dst=arp_packet.dst_ip)
                    actions = [parser.OFPActionOutput(5), parser.OFPActionSetField(ipv4_dst='10.0.0.5')]
                    self.add_flow(datapath, 1, match, actions)


                    #install flow for traffic returning from h5
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, in_port=5, ipv4_dst=arp_packet.src_ip)
                    actions = [parser.OFPActionOutput(in_port), parser.OFPActionSetField(ipv4_src=arp_packet.dst_ip)]
                    self.add_flow(datapath, 1, match, actions)


                    #Send ARP response matching reqwst to "next" roun robin server
                    print('sending arp reply with 10.0.0.5')
                    e = ethernet.ethernet(dst=src, src='00:00:00:00:00:05', ethertype=ether.ETH_TYPE_ARP)
                    a = arp.arp(hwtype=1, proto=0x0800, hlen=6, plen=4, opcode=2, src_mac='00:00:00:00:00:05', src_ip=arp_packet.dst_ip, dst_mac=src, dst_ip=arp_packet.src_ip)
                    arp_reply = packet.Packet()
                    arp_reply.add_protocol(e)
                    arp_reply.add_protocol(a)
                    out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=ofproto.OFPP_IN_PORT, actions=[], data=arp_reply)
                    datapath.send_msg(out)

                    robin_value = 2

                else:

                    #install flow for traffic to h5	
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, in_port=in_port, ipv4_dst=arp_packet.dst_ip)
                    actions = [parser.OFPActionOutput(6), parser.OFPActionSetField(ipv4_dst='10.0.0.6')]
                    self.add_flow(datapath, 1, match, actions)


                    #install flow for traffic returning from h5
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, in_port=6, ipv4_dst=arp_packet.src_ip)
                    actions = [parser.OFPActionOutput(in_port), parser.OFPActionSetField(ipv4_src=arp_packet.dst_ip)]
                    self.add_flow(datapath, 1, match, actions)

                    #Send ARP response matching reqwst to "next" round robin server
                    print('sending arp reply with 10.0.0.6')
                    e = ethernet.ethernet(dst=src, src='00:00:00:00:00:06', ethertype=ether.ETH_TYPE_ARP)
                    a = arp.arp(hwtype=1, proto=0x0800, hlen=6, plen=4, opcode=2, src_mac='00:00:00:00:00:06', src_ip=arp_packet.dst_ip, dst_mac=src, dst_ip=arp_packet.src_ip)
                    arp_reply = packet.Packet()
                    arp_reply.add_protocol(e)
                    arp_reply.add_protocol(a)
                    out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=ofproto.OFPP_IN_PORT, actions=[], data=arp_reply)
                    datapath.send_msg(out)

                    robin_value = 1



        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
        print("round robin is %s", robin_value)

