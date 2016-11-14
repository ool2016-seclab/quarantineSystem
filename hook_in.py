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
from ryu.app.rest_router import OfCtl

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

    #Packet_inのハンドラが呼ばれる
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        #パケットから送信元のIP・MAC・宛先のIP・MAC・dataを取得
        msg = ev.msg
        datapath = msg.datapath
        #ofctl = OfCtl.factory(dp=datapath, logger=self.logger)
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
        header_list = []
        for p in pkt.protocols:
            if type(p) != str:
                self.logger.info(":::aaa:::{}".format(type(p)))
                header_list.append(dict(protocol_name=p))
                self.logger.info(":::bbb:::")
                           
        if self.__DEBUG_MODE__:
            self.logger.info("HEADER:{}".format(header_list))
        if not ETHERNET in header_list:
            if self.__DEBUG_MODE__:
                self.logger.info("Not Ether type")
            return
        #[swのid(dpid)][MACAddr]のテーブルにSwitch input portを登録
        self.mac_to_port[dpid][header_list[ETHERNET].src] = in_port
        dp_dict = {
            'dp':datapath,
            'ofproto':ofproto,
            'parser':parser,
            'dpid':dpid,
            'in_port':in_port
            }
        #arpパケット
        if ARP in header_list:
            self._packet_in_arp(msg, header_list, dp_dict)
            return
        elif IPV4 in header_list:
            self._packet_in_ipv4(msg, header_list, dp_dict)
        else:
            #IPV6 or others?
            return


    def _packet_in_arp(self, msg, header_list, dp_dict):
        # ARP packet handling.
        dp = dp_dict["dp"]
        ofproto = dp_dict["ofproto"]
        parser = dp_dict["parser"]
        dpid = dp_dict["dpid"]
        in_port = dp_dict["in_port"]
        src_ip = header_list[ARP].src_ip
        dst_ip = header_list[ARP].dst_ip

        if src_ip == dst_ip:
            # GARP -> packet forward (normal)
            output = ofproto.OFPP_NORMAL
         
            self.logger.info('Receive GARP from [%s].', src_ip,
                             extra=dpid)
            self.logger.info('Send GARP (normal).', dpid)
        self._packet_out(msg, header_list, dp_dict)

    def _packet_in_ipv4(self, msg, header_list, dp_dict):
        pkt_dict = dict()
        pkt_dict["ipv4"] = {
            "src": int(netaddr.IPAddress(header_list[IPV4].src)),
            "dst": int(netaddr.IPAddress(header_list[IPV4].dst)),
            }
        pkt_dict["data"] = msg.data
        self.send_qsys(msg, pkt_dict, header_list, dp_dict)
        
    def send_qsys(self, msg, pkt_dict, header_list, dp_dict):
        if self.__DEBUG_MODE__:
            self.logger.info("Qsys_in{}".format(pkt_dict))
        result = Qsys().send(pkt_dict)
        if result == True:
            self._packet_out(msg,header_list, dp_dict)
            return
        #Drop Packet
        self.logger.info('Drop:{}'.format(pkt_dict))
        return 

    def _packet_out(self, msg, header_list, dp_dict):
        dp = dp_dict["dp"]
        ofproto = dp_dict["ofproto"]
        parser = dp_dict["parser"]
        dpid = dp_dict["dpid"]
        in_port = dp_dict["in_port"]
        #Transport to dst
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
        out = parser.OFPPacketOut(
            datapath=dp, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=msg.data)
        dp.send_msg(out)