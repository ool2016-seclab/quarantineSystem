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
import tempfile
ETHERNET = ethernet.ethernet
VLAN = vlan.vlan
IPV4 = ipv4.ipv4
ARP = arp.arp
ICMP = icmp.icmp
TCP = tcp.tcp
UDP = udp.udp
STREAM = stream_parser.StreamParser
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

    #Packet_inのハンドラが呼ばれる
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """パケットから送信元のIP・MAC・宛先のIP・MAC・dataを取得"""
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
        qsys_pkt = QsysDataStruct(self.logger)
        eth = pkt.get_protocol(ETHERNET)
        if not eth:
            if self.__DEBUG_MODE__:
                self.logger.info("Not Ether type")
            return
        qsys_pkt.set_eth(eth)#qsys_pktにethを登録
        #[swのid(dpid)][MACAddr]のテーブルにSwitch input portを登録
        self.mac_to_port[dpid][eth.src] = in_port
            
        #arpパケット
        arp = pkt.get_protocol(ARP)
        ipv4 = pkt.get_protocol(IPV4)
        if arp:
            qsys_pkt.set_arp(arp)
            ipv4_src = qsys_pkt.get_ipv4Addr_src()
            self.logger.info("ipv4_src:{}".format(ipv4_src))
            self.mac_to_ipv4[eth.src] = ipv4_src
            if QsysRelEval.UNKNOWN == self.qsys.get_reliability_eval(ipv4_src):
                self.qsys.regist_client(qsys_pkt)
            self._packet_in_arp(msg, pkt, qsys_pkt, dp)
            return
        elif ipv4:
            qsys_pkt.set_ipv4(ipv4)
            ipv4_src = qsys_pkt.get_ipv4Addr_src()
            self.mac_to_ipv4[eth.src] = ipv4_src
            if QsysRelEval.UNKNOWN == self.qsys.get_reliability_eval(ipv4_src):
                self.qsys.regist_client(qsys_pkt)
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
        src_ip = qsys_pkt.get_ipv4Addr_src()
        dst_ip = qsys_pkt.get_ipv4Addr_dst()

        if src_ip == dst_ip:
            # GARP -> packet forward (normal)
            #TODO
            #output = ofproto.OFPP_NORMAL
            #self.logger.info('Receive GARP from [%s].', src_ip, extra=dpid)
            #self.logger.info('Send GARP (normal).', dpid)
            return
        #arpはそのまま流す
        self._packet_out(msg, qsys_pkt, dp)

    def _packet_in_ipv4(self, msg, pkt, qsys_pkt, dp):
        _tcp = pkt.get_protocol(TCP)
        if _tcp:
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
                    continue
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
from ryu.lib.pcaplib import *
class RyuPcapToBytes(pcaplib.Writer):
    def __init__(self, snaplen=65535, network=1):
        self.snaplen = snaplen
        self.network = network
        self._write_pcap_file_hdr()

    def _write_pcap_file_hdr(self):
        pcap_file_hdr = PcapFileHdr(snaplen=self.snaplen,
                                    network=self.network)
        self.fh = (pcap_file_hdr.serialize())

    def _write_pkt_hdr(self, ts, buf_len):
        sec = int(ts)
        usec = int(round(ts % 1, 6) * 1e6) if sec != 0 else 0

        pc_pkt_hdr = PcapPktHdr(ts_sec=sec, ts_usec=usec,
                                incl_len=buf_len, orig_len=buf_len)

        return (pc_pkt_hdr.serialize())

    def write_pkt(self, buf, ts=None):
        res = self.fh
        ts = time.time() if ts is None else ts

        # Check the max length of captured packets
        buf_len = len(buf)
        if buf_len > self.snaplen:
            buf_len = self.snaplen
            buf = buf[:self.snaplen]

        res += self._write_pkt_hdr(ts, buf_len)

        res += (buf)

        return res

    def __del__(self):
        pass
        #self._f.close()

from dpkt.pcap import *
class DpktPcapFromBytes(dpkt.pcap.Reader):
    def __init__(self, fh, ph):
        #self.name = getattr(fileobj, 'name', '<%s>' % fileobj.__class__.__name__)
        #self.__f = fileobj
        #buf = self.__f.read(FileHdr.__hdr_len__)
        buf = ph
        #self.__fh = FileHdr(fh.FileHdr.__hdr_len__))
        self.__ph = PktHdr
        if self.__fh.magic == PMUDPCT_MAGIC:
            self.__fh = LEFileHdr(buf)
            self.__ph = LEPktHdr
        elif self.__fh.magic != TCPDUMP_MAGIC:
            raise ValueError('invalid tcpdump header')
        if self.__fh.linktype in dltoff:
            self.dloff = dltoff[self.__fh.linktype]
        else:
            self.dloff = 0
        self.snaplen = self.__fh.snaplen
        self.filter = b''
        self.__iter = iter(self)
