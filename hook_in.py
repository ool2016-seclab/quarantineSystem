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
import netaddr
from builtins import dict
from ryu.lib import hub
#import time
from qsys import Qsys, QsysPkt, QsysRelEval

ETHERNET = ethernet.ethernet
VLAN = vlan.vlan
IPV4 = ipv4.ipv4
ARP = arp.arp
ICMP = icmp.icmp
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
        self.datapathes = []#[[dp,parser],]
        self.qsys = Qsys()
        self.mac_to_port = {}#{[dpid][addr] = in_port
        self.mac_to_ipv4 = {}#[addr] = ipv4
        self.mac_deny_list = {}#List deny arrival(qsys eval is low)
        self.monitor_thread = hub.spawn(self.update_mac_deny_list)
       # self.update_mac_deny_list()
        
    #コントローラにSWが接続される
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.datapathes.append([datapath,parser])
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
            if self.__DEBUG_MODE__:
                self.logger.info("packet-in {}".format(pkt))
        except:
            self.logger.debug("malformed packet")
            return
        qsys_pkt = QsysPkt()
        eth = pkt.get_protocol(ETHERNET)
        if not eth:
            if self.__DEBUG_MODE__:
                self.logger.info("Not Ether type")
            return
        qsys_pkt.set_eth(eth)
        #[swのid(dpid)][MACAddr]のテーブルにSwitch input portを登録
        self.mac_to_port[dpid][eth.src] = in_port
            
        
        #arpパケット
        arp = pkt.get_protocol(ARP)
        ipv4 = pkt.get_protocol(IPV4)
        if arp:
            qsys_pkt.set_arp(arp)
            self.mac_to_ipv4[eth.src] = arp.src_ip
            self.qsys.regist_client(qsys_pkt)
            self._packet_in_arp(msg, pkt, qsys_pkt, dp)
            return
        elif ipv4:
            qsys_pkt.set_ipv4(ipv4)
            self.mac_to_ipv4[eth.src] = ipv4.src
            self.qsys.regist_client(qsys_pkt)
            self._packet_in_ipv4(msg, pkt, qsys_pkt, dp)
        else:
            #IPV6 or others?
            return
    def _packet_in_arp(self, msg, pkt, qsys_pkt, dp):
        # ARP packet handling.
        datapath = dp.datapath
        dpid = dp.dpid
        ofproto = dp.ofproto
        parser = dp.parser
        in_port = dp.in_port
        src_ip = qsys_pkt.arp.src_ip
        dst_ip = qsys_pkt.arp.dst_ip



        if src_ip == dst_ip:
            # GARP -> packet forward (normal)
            #TODO
            #output = ofproto.OFPP_NORMAL
         
            self.logger.info('Receive GARP from [%s].', src_ip,
                             extra=dpid)
            self.logger.info('Send GARP (normal).', dpid)
        self._packet_out(msg, qsys_pkt, dp)

    def _packet_in_ipv4(self, msg, pkt, qsys_pkt, dp):
        qsys_pkt.data =msg.data
        self.send_qsys(msg, qsys_pkt, dp)
   
    def send_qsys(self, msg, qsys_pkt,  dp):
        if self.__DEBUG_MODE__:
            self.logger.info("Qsys_in{}".format(qsys_pkt))
        result = self.qsys.send(qsys_pkt)
        if True == result:
            self._packet_out(msg, qsys_pkt, dp)
            return
        else:#Drop Packet
            self.logger.info('Drop:{}'.format(qsys_pkt))
            return 

    def _packet_out(self, msg, qsys_pkt, dp):
        datapath = dp.datapath
        dpid = dp.dpid
        ofproto = dp.ofproto
        parser = dp.parser
        in_port = dp.in_port
        #Transport to dst
        src_eth = qsys_pkt.eth.src
        dst_eth = qsys_pkt.eth.dst
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

    def update_mac_deny_list(self):
        while True:
            ip_to_mac = {v:k for k, v in self.mac_to_ipv4.items()}
            self.logger.info("ip_to_mac{}".format(ip_to_mac))
            for ip, mac in ip_to_mac.items():
                if QsysRelEval.LOW == self.qsys.get_reliability_eval(ip):
                    if not self.mac_deny_list[mac]:
                        for dp in self.datapathes:#dp[0]:dp,dp[1]:parser
                            match = dp[1].OFPMatch(eth_arc=eth)
                            actions = []#Drop
                            self.add_flow(dp, 0,match, actions)
                        self.mac_deny_list.update(mac,ip)
           #    self.mac_deny_list.update()
            self.qsys.update_reliability_level("10.0.0.1", 0)
            hub.sleep(10)


