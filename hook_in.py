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
from ryu.lib import pcaplib
import netaddr
from builtins import dict
from ryu.lib import hub
#import time
from qsys import Qsys, QsysDataStruct, QsysRelEval
import dpkt

ETHERNET = ethernet.ethernet
VLAN = vlan.vlan
IPV4 = ipv4.ipv4
ARP = arp.arp
ICMP = icmp.icmp
TCP = tcp.tcp
UDP = udp.udp

class Dp_obj:
    """datapathのオブジェクトをまとめるためのクラス
    """
    def __init__(self, msg):
        self.datapath = msg.datapath
        self.dpid = self.datapath.id
        self.ofproto = self.datapath.ofproto
        self.parser = self.datapath.ofproto_parser
        #スイッチのポート
        self.in_port = msg.match['in_port']

class SystemActionModei(enum.Enum):
    """学習モード(正常時のデータを記録するためのモード)と
    異常検知モード"""
   # あとでモード実装するはず？
    learn = 0
    quarantine = 1

class QsysTest(SimpleSwitch13):
    __DEBUG_MODE__ = False #:on,F:off
	#動作モード
    #ACTION_MODE = SystemActionMode.quarantine

    def __init__(self, *args, **kwargs):
        super(QsysTest, self).__init__(*args, **kwargs)
        self.datapathes = []    #[[dp,parser],]
        self.qsys = Qsys(self.logger)      #Qsys object
        self.mac_to_port = {}   #{dpid:{addr:in_port}}
        self.mac_to_ipv4 = {}   #{mac:ipv4}
        self.mac_deny_list = {} #{mac:ipv4}到達拒否のClientのリスト
                                #到達拒否のClientで、swに拒否フローを流し込み終わったもの
        self.gateway = {}#デフォルトゲートウェイ(ハード－コード){ipv4:eth}
        self.gateway['192.168.1.254'] = '00:00:00:00:00:01'
        self.gateway['192.168.2.254'] = '00:00:00:00:00:02'
        self.monitor_thread = hub.spawn(self.update_mac_deny_list)#
        
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
    def set_mac_to_port(self, dpid, eth_src, in_port):
        #送信元MACと送信元SWのポートの対応関係を記録
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth_src] = in_port
    def get_port_from_mac(self, dpid, eth):
        if eth in self.mac_to_port[dpid]:
            return self.mac_to_port[dpid][eth]
        else:
            return None
    def set_mac_to_ipv4(self, eth_src, ipv4_src):
        ipaddr = self.mac_to_ipv4.setdefault(eth_src,ipv4_src)
        if ipaddr in self.gateway:
            self.mac_to_ipv4.setdefault(eth_src,ipv4_src)
        else:
            if ipaddr != ipv4_src:
                self.logger.info("The correspondence between MAC and IP has changed\n\
                {mac_old}:{ip_old}→{ip_new}".format(mac_old=eth_src,ip_old=ipaddr, ip_new=ipv4_src))
                #TODO:Qsys上のClientのMACアドレスとIPの対応関係変更
            self.mac_to_ipv4[eth_src] = ipv4_src
    def get_ipv4_from_mac(self, eth):
        if eth in self.mac_to_ipv4:
            return self.mac_to_ipv4[eth]
        else:
            return None
    #Packet_inのハンドラが呼ばれる
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """パケットから送信元のIP・MAC・宛先のIP・MAC・dataを取得"""
        msg = ev.msg
        dp = Dp_obj(msg)
        dpid = dp.dpid
        in_port = dp.in_port#スイッチのポート
        qsys_pkt = QsysDataStruct(self.logger)

        #パケットのヘッダ情報を取得
        try:
            pkt = packet.Packet(msg.data)
            if self.__DEBUG_MODE__:
                self.logger.info("packet-in {}".format(pkt))
        except:
            self.logger.debug("malformed packet")
            return
        eth = pkt.get_protocol(ETHERNET)
        if not eth:
            if self.__DEBUG_MODE__:
                self.logger.info("Not Ether type")
            return
        qsys_pkt.set_eth(eth)#qsys_pktにethを登録
        eth_src = eth.src
        #[swのid(dpid)][MACAddr]のテーブルにSwitch input portを登録
        self.set_mac_to_port(dpid, eth_src, in_port) 
        #arpパケット
        arp = pkt.get_protocol(ARP)
        ipv4 = pkt.get_protocol(IPV4)
        if arp:
            qsys_pkt.set_arp(arp)
            ipv4_src = qsys_pkt.get_ipv4Addr_src()
            if self.__DEBUG_MODE__:
                self.logger.info("ipv4_src:{}".format(ipv4_src))
            self.set_mac_to_ipv4(eth_src, ipv4_src)
            self._packet_in_arp(msg, pkt, qsys_pkt, dp)
            return
        elif ipv4:
            qsys_pkt.set_ipv4(ipv4)
            ipv4_src = qsys_pkt.get_ipv4Addr_src()
            self.mac_to_ipv4[eth.src] = ipv4_src
            self._packet_in_ipv4(msg, pkt, qsys_pkt, dp)
            return
        else:
            self.logger.info("Others Pkt:{}".format(msg))
            #IPV6 or others?
            return
    def _packet_in_arp(self, msg, pkt, qsys_pkt, dp):
        # ARP packet handling.
        #datapath = dp.datapath
        #dpid = dp.dpid
        #ofproto = dp.ofproto
        #parser = dp.parser
        #in_port = dp.in_port
        src_eth = qsys_pkt.get_ethAddr_src()
        dst_eth = qsys_pkt.get_ethAddr_dst()
        src_ip = qsys_pkt.get_ipv4Addr_src()
        dst_ip = qsys_pkt.get_ipv4Addr_dst()

        if src_ip == dst_ip:
            # GARP -> packet forward (normal)
            #TODO
            #output = ofproto.OFPP_NORMAL
            #self.logger.info('Receive GARP from [%s].', src_ip, extra=dpid)
            #self.logger.info('Send GARP (normal).', dpid)
            return
        #gatewayへのarp
        if dst_ip in self.gateway:
            gw_eth = gateway[dst_ip]
            opcode = qsys_pkt.get_arpObj().opcode
            if opcode == 1:#ARP Request
                self.send_arp(dp.datapath, 2, gw_eth, src_ip, dst_eth, dst_ip, dp.in_port)
                return
            elif opcode == 2:#ARP_Reply
                pass#TODO
        else:
            #arpはそのまま流す
            self._packet_out(msg, qsys_pkt, dp)
    def send_arp(self, datapath, opcode, srcMac, srcIp, dstMac, dstIp, outPort, RouteDist=None):
        if opcode == 1:
            self.portInfo[outPort] = PortTable(outPort, srcIp, srcMac, RouteDist)

            targetMac = "00:00:00:00:00:00"
            targetIp = dstIp
        elif opcode == 2:
            targetMac = dstMac
            targetIp = dstIp

        e = ethernet(dstMac, srcMac, ether.ETH_TYPE_ARP)
        a = arp(1, 0x0800, 6, 4, opcode, srcMac, srcIp, targetMac, targetIp)
        p = Packet()
        p.add_protocol(e)
        p.add_protocol(a)
        p.serialize()

        actions = [datapath.ofproto_parser.OFPActionOutput(outPort, 0)]
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=0xffffffff,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=p.data)
        datapath.send_msg(out)
        return 0
    def _packet_in_ipv4(self, msg, pkt, qsys_pkt, dp):
        _tcp = pkt.get_protocol(TCP)
        if _tcp:
            self.logger.info("tcp:{}".format(_tcp))
            f = open('tmp','wb')
            pcap = pcaplib.Writer(f).write_pkt(msg.data)
            f.close()
            f = open('tmp', 'rb')
            payload = dpkt.pcap.Reader(f)
            for t,k in payload:
                eth = dpkt.ethernet.Ethernet(k)
                ip = eth.data
                __tcp = ip.data
                self.logger.info("payload:{}".format(__tcp))
                try:
                    request = dpkt.http.Request(__tcp.data)
                    url = http.headers['host'] + http.uri
                    self.logger.info("http:{}".format(url))
                except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                    pass
                except:
                    pass
            f.close()
            self.logger.info("data:{}".format(msg.data))
        qsys_pkt.set_data(msg.data)
        self.send_qsys(msg, qsys_pkt, dp)
   
    def send_qsys(self, msg, qsys_pkt,  dp):
        if self.__DEBUG_MODE__:
            self.logger.info("send_qsys{}".format(qsys_pkt))
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
        """低信頼度のClientをpacket_inしないようswitchにflowを流し込む。
        スレッドとして立ち上げ定期的に実行する"""
        #TODO:そのうちqsysからのイベントで呼び出せるようにしたい
        while True:
            ip_to_mac = {v:k for k, v in self.mac_to_ipv4.items()}
            self.logger.info("ip_to_mac{}".format(ip_to_mac))
            for ip, eth in ip_to_mac.items():
                self.logger.info("IP:{}".format(ip))
                self.logger.info("Level:{}".format(self.qsys.get_reliability_level(ip)))
                eval = self.qsys.get_reliability_eval(ip)
                if QsysRelEval.LOW == eval:
                    if not eth in self.mac_deny_list:
                        for dp in self.datapathes:#dp[0]:dp,dp[1]:parser
                            match = dp[1].OFPMatch(eth_src=eth)
                            actions = []#Drop
                            self.add_flow(dp[0], 10,match, actions)
                        self.mac_deny_list.update({eth:ip})#拒否済に追加
                elif QsysRelEval.UNKNOWN == eval:
                    #TODO:登録されていないClientを参照した際の例外処理
                    pass
            self.qsys.update_reliability_level('10.0.0.1', 1)#テストコード。10.0.0.1の信頼度を1(< LOW)に
            self.logger.info("mac_to_port:{}".format( self.mac_to_port ))
            hub.sleep(5)