#-*- co ding: utf-8 -*-
import json
import enum 
from ryu.app.simple_switch_13 import SimpleSwitch13
from ryu.controller  import ofp_event, event
from ryu.controller.handler import set_ev_cls,MAIN_DISPATCHER,CONFIG_DISPATCHER
from ryu.ofproto.ofproto_v1_3 import *
from ryu.ofproto.ofproto_v1_3_parser import OFPMatch
from ryu.ofproto.ofproto_parser import *
from ryu.lib.packet import *
from ryu.controller import dpset
from qsys import Qsys
import netaddr
from builtins import dict
#import time

ETHERNET = ethernet.ethernet
VLAN = vlan.vlan
IPV4 = "ipv4.ipv4"
ARP = "arp.arp"
ICMP = "icmp.icmp"
TCP = tcp.tcp
UDP = udp.udp

class Dp_obj:
    def __init__(self, msg):
        self.datapath = msg.datapath
        self.dpid = self.datapath.id
        self.ofproto = self.datapath.ofproto
        self.parser = self.datapath.ofproto_parser
        #スイッチのポート
        self.in_port = msg.match['in_port']

class SystemActionModei(enum.Enum):
   # あとでモード実装するはず？
    learn = 0
    quarantine = 1

class QsysTest(SimpleSwitch13):
    __DEBUG_MODE__ = False #:on,F:off
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

    #Packet_inのハンドラが呼ばれる
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        #パケットから送信元のIP・MAC・宛先のIP・MAC・dataを取得
        msg = ev.msg
        dp = Dp_obj(msg)
        datapath = dp.datapath
        dpid = dp.dpid
        ofproto = dp.ofproto
        parser = dp.parser
        #スイッチのポート
        in_port = dp.in_port
        #送信元MACと送信元SWのポートの対応関係を記録
        self.mac_to_port.setdefault(dpid, {})
        #パケットのヘッダ情報を取得
        try:
            pkt = packet.Packet(msg.data)
            #if self.__DEBUG_MODE__:
            self.logger.info("packet-in {}".format(pkt))
        except:
            self.logger.debug("malformed packet")
            return
        pkt_dict = dict()
        eth = pkt.get_protocol(ETHERNET)
        if not eth:
           # if self.__DEBUG_MODE__:
            self.logger.info("Not Ether type")
            return
        pkt_dict.update(ETH,eth)
        #[swのid(dpid)][MACAddr]のテーブルにSwitch input portを登録
        self.mac_to_port[dpid][eth.src] = in_port
        #arpパケット
        arp = pkt.get_protocol(ARP)
        ipv4 = pkt.get_protocol(IPV4)
        if arp:
            pkt_dict.update(ARP,arp)
            self._packet_in_arp(msg, pkt, pkt_dict, dp)
            return
        elif ipv4:
            pkt_dict.update(IPV4,ipv4)
            self._packet_in_ipv4(msg, pkt, pkt_dict, dp)
        else:
            #IPV6 or others?
            return
    def _packet_in_arp(self, msg, pkt, pkt_dict, dp):
        # ARP packet handling.
        datapath = dp.datapath
        dpid = dp.dpid
        ofproto = dp.ofproto
        parser = dp.parser
        in_port = dp.in_port
        src_ip = pkt_dict[ARP].src_ip
        dst_ip = pkt_dict[ARP].dst_ip

        if src_ip == dst_ip:
            # GARP -> packet forward (normal)
            output = ofproto.OFPP_NORMAL
         
            self.logger.info('Receive GARP from [%s].', src_ip,
                             extra=dpid)
            self.logger.info('Send GARP (normal).', dpid)
        self._packet_out(msg, pkt, dp)

    def _packet_in_ipv4(self, msg, pkt, pkt_dict, dp):
        pkt_dict.update(["data"],msg.data)
        self.send_qsys(msg, pkt_dict, dp)
        
    def send_qsys(self, msg, pkt_dict,  dp):
        if self.__DEBUG_MODE__:
            self.logger.info("Qsys_in{}".format(pkt_dict))
        result = Qsys().send(pkt_dict)
        if result == True:
            self._packet_out(msg, pkt_dict, dp)
            return
        #Drop Packet
        self.logger.info('Drop:{}'.format(pkt_dict))
        return 

    def _packet_out(self, msg, pkt_dict, dp):
        datapath = dp.datapath
        dpid = dp.dpid
        ofproto = dp.ofproto
        parser = dp.parser
        in_port = dp.in_port
        #Transport to dst
        src_eth = pkt_dict[ETHERNET].src
        dst_eth = pkt_dict[ETHERNET].dst
        #該当するSWの中にMacAddrがあるか？
        if dst_eth in self.mac_to_port[dpid]:
            #Switch output portをテーブルから指定
            out_port = self.mac_to_port[dpid][dst_eth]
        else:
            #フラッディング
            out_port = ofproto.OFPP_FLOOD
        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=msg.data)
        datapath.send_msg(out)