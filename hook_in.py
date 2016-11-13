#-*- co ding: utf-8 -*-
import json
import enum 
from ryu.app.simple_switch_13 import SimpleSwitch13
from ryu.controller  import ofp_event, event
from ryu.controller.handler import set_ev_cls,MAIN_DISPATCHER,CONFIG_DISPATCHER
from ryu.ofproto.ofproto_v1_3 import *
from ryu.ofproto.ofproto_v1_3_parser import OFPMatch
from ryu.ofproto.ofproto_parser import *
from ryu.lib.packet import packet
from ryu.lib.packet import *
from ryu.controller import dpset
from qsys import Qsys
import netaddr
from builtins import dict
import time

ETHERNET = ethernet.ethernet.__name__
VLAN = vlan.vlan.__name__
IPV4 = ipv4.ipv4.__name__
ARP = arp.arp.__name__
ICMP = icmp.icmp.__name__
TCP = tcp.tcp.__name__
UDP = udp.udp.__name__

class SystemActionModei(enum.Enum):
   # あとでモード実装するはず？
    learn = 0
    quarantine = 1

class QsysTest(SimpleSwitch13):
    __DEBUG_MODE__ = False#T:on,F:off
	#動作モード
    #ACTION_MODE = SystemActionMode.quarantine

    def __init__(self, *args, **kwargs):
        super(QsysTest, self).__init__(*args, **kwargs)
        self.mac_to_port = {}#{[dpid][addr] = in_port}

    #コントローラにSWが接続される
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.logger.info("Simple_Switch13_features")
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
    def test(self, dp_dict):
        return
    def test2(self, msg):
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        #スイッチのポート
        in_port = msg.match['in_port']
        return
    #Packet_inのハンドラが呼ばれる
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        #パケットから送信元のIP・MAC・宛先のIP・MAC・dataを取得
        allowTransportFlag = False
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        #スイッチのポート
        in_port = msg.match['in_port']
        #送信元MACと送信元SWのポートの対応関係を記録
        self.mac_to_port.setdefault(dpid, {})
        pkt = packet.Packet(msg.data)

        if self.__DEBUG_MODE__:
            self.logger.info("packet-in {}".format(pkt))
        #パケットのヘッダ情報を取得
        header_list = dict((p.protocol_name, p)for p in pkt.protocols if type(p) != str)
        if self.__DEBUG_MODE__:
            self.logger.info("HEADER:{}".format(header_list))
        if not ETHERNET in header_list:
            if self.__DEBUG_MODE__:
                self.logger.info("Not Ether type")
            return
 
        #[swのid][MACAddr]のテーブルにSwitch input portを登録
        self.mac_to_port[dpid][header_list[ETHERNET].src] = in_port
        
        start = time.time()
        for i in range(0,100):
            dp_dict = {
                'dp':datapath,
                'ofproto':ofproto,
                'parser':parser,
                'dpid':dpid,
                'in_port':in_port
                }
            self.test(dp_dict)
        elapsed_time = time.time() - start
        print ("elapsed_time:{0}".format(elapsed_time)) + "[sec]"
        start = time.time()
        for i in range(0,100):
            self.test2(msg)
        elapsed_time = time.time() - start
        print ("elapsed_time:{0}".format(elapsed_time)) + "[sec]"
        return
        #arpパケット
        if ARP in header_list:
            self._packet_in_arp(msg, header_list)
            return
        if IPV4 in header_list:
            self._packet_in_ipv4(msg, header_list, pkt_dict)
        else:
            # Packet to internal host or gateway router.
            #self._packetin_to_node(msg, header_list)
            return

    def _packet_in_arp(self, msg, header_list=dict()):
        src_addr = self.address_data.get_data(ip=header_list[ARP].src_ip)
        if src_addr is None:
            return

        # ARP packet handling.
        in_port = self.ofctl.get_packetin_inport(msg)
        src_ip = header_list[ARP].src_ip
        dst_ip = header_list[ARP].dst_ip
        srcip = ip_addr_ntoa(src_ip)
        dstip = ip_addr_ntoa(dst_ip)

        if src_ip == dst_ip:
            # GARP -> packet forward (normal)
            output = self.ofctl.dp.ofproto.OFPP_NORMAL
         
            self.logger.info('Receive GARP from [%s].', srcip,
                             extra=self.sw_id)
            self.logger.info('Send GARP (normal).', extra=self.sw_id)

            if (dst_addr is not None and
                    src_addr.address_id == dst_addr.address_id):
                # ARP from internal host -> packet forward (normal)
                output = self.ofctl.dp.ofproto.OFPP_NORMAL
                self.ofctl.send_packet_out(in_port, output, msg.data)

                self.logger.info('Receive ARP from an internal host [%s].',
                                 srcip, extra=self.sw_id)
                self.logger.info('Send ARP (normal)', extra=self.sw_id)
        else:
            if header_list[ARP].opcode == arp.ARP_REQUEST:
                # ARP request to router port -> send ARP reply
                src_mac = header_list[ARP].src_mac
                dst_mac = self.port_data[in_port].mac
                arp_target_mac = dst_mac
                output = in_port
                in_port = self.ofctl.dp.ofproto.OFPP_CONTROLLER

                self.ofctl.send_arp(arp.ARP_REPLY, self.vlan_id,
                                    dst_mac, src_mac, dst_ip, src_ip,
                                    arp_target_mac, in_port, output)

                log_msg = 'Receive ARP request from [%s] to router port [%s].'
                self.logger.info(log_msg, srcip, dstip, extra=self.sw_id)
                self.logger.info('Send ARP reply to [%s]', srcip,
                                 extra=self.sw_id)

            elif header_list[ARP].opcode == arp.ARP_REPLY:
                #  ARP reply to router port -> suspend packets forward
                log_msg = 'Receive ARP reply from [%s] to router port [%s].'
                self.logger.info(log_msg, srcip, dstip, extra=self.sw_id)

                packet_list = self.packet_buffer.get_data(src_ip)
                if packet_list:
                    # stop ARP reply wait thread.
                    for suspend_packet in packet_list:
                        self.packet_buffer.delete(pkt=suspend_packet)

                    # send suspend packet.
                    output = self.ofctl.dp.ofproto.OFPP_TABLE
                    for suspend_packet in packet_list:
                        self.ofctl.send_packet_out(suspend_packet.in_port,
                                                   output,
                                                   suspend_packet.data)
                        self.logger.info('Send suspend packet to [%s].',
                                         srcip, extra=self.sw_id)

    def _packet_in_ipv4(self, msg, header_list=dict()):
        pkt_dict = dict()
        pkt_dict["ipv4"] = {
            "src": int(netaddr.IPAddress(header_list[IPV4].src)),
            "dst": int(netaddr.IPAddress(header_list[IPV4].dst)),
            }
        pkt_dict["eth"] = {
                'src':_eth.src,
                'dst':_eth.dst,
                }
        pkt_dict["data"] = msg.data
        self.send_qsys(msg, pkt_dict)
        
    def send_qsys(self, msg, pkt_dict=dict()):
        if self.__DEBUG_MODE__:
            self.logger.info("Qsys_in{}".format(pkt_dict))
        result = Qsys().send(pkt_dict)
        if result == True:
            self._packet_out(msg,pkt_dict)
            return
        #Drop Packet
        self.logger.info('Drop:{}'.format(pkt_dict))
        return 

    def _packet_out(self, msg, header_list=dict()):
        #Transport to dst
        src_ip = ip_addr_ntoa(header_list[IPV4].src)
        dst_ip = ip_addr_ntoa(header_list[IPV4].dst)
        src_eth = header_list[ETHERNET].src
        dst_eth = header_list[ETHERNET].dst
        #該当するSWの中にMacAddrがあるか？
        if dst_eth in self.mac_to_port[dpid]:
            #Switch output portをテーブルから指定
            out_port = self.mac_to_port[dpid][dst_eth]
        else:
            #フラッディング
            out_port = ofproto.OFPP_FLOOD
        actions = [parser.OFPActionOutput(out_port)]
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=msg.data)
        datapath.send_msg(out)
    def _packet_out_flood(self, msg, header_list=dict()):
        #フラッディング
        out_port = ofproto.OFPP_FLOOD
        actions = [parser.OFPActionOutput(out_port)]
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=msg.data)
        datapath.send_msg(out)