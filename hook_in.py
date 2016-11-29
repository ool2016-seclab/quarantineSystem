#-*- co ding: utf-8 -*-
import sys
import json
import enum 
from ryu.app.simple_switch_13 import SimpleSwitch13
from ryu.controller  import ofp_event, event
from ryu.controller.controller import Datapath
from ryu.controller.handler import set_ev_cls,MAIN_DISPATCHER,CONFIG_DISPATCHER
from ryu.ofproto.ofproto_v1_3 import *
from ryu.ofproto.ofproto_v1_3_parser import OFPMatch
from ryu.ofproto import ofproto_v1_3_parser
from ryu.ofproto.ofproto_parser import *
from ryu.lib.packet import *
from ryu.controller import dpset
from ryu.lib import pcaplib
import netaddr
from builtins import dict, isinstance
from ryu.lib import hub
import time
from datetime import datetime
from qsys import *
import dpkt
from ryu.controller.event import EventBase
from io import BytesIO
from rainbow_logging_handler import RainbowLoggingHandler

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
        #self.datapath = Datapath()#inteliSense用
        #self.ofproto = ofproto_v1_3#inteliSense用
        self.datapath = msg.datapath
        self.dpid = self.datapath.id
        self.ofproto = self.datapath.ofproto
        self.parser = self.datapath.ofproto_parser
        #スイッチのポート
        self.in_port = None
        if not isinstance(msg, ofproto_v1_3_parser.OFPSwitchFeatures):
            self.in_port = msg.match['in_port']
                

class SystemActionModei(enum.Enum):
    """学習モード(正常時のデータを記録するためのモード)と
    異常検知モード"""
   # あとでモード実装するはず？
    learn = 0
    quarantine = 1
class GatewayList:
    def __init__(self):
        g1 = Gateway(eth='00:00:5E:00:53:00',ip_addr='192.168.1.254', mask=24)
        g2 = Gateway(eth='00:00:5E:00:53:01',ip_addr='192.168.2.254', mask=24)
        self.list = [g1, g2]
    def get_all(self):
        return self.list
    def get_ip_addr(self, eth):
        for v in self.list:
            assert isinstance(v, Gateway)
            if v.get_eth() == eth:
                return v.ip_addr
        return None
    def get_eth(self, ip_addr):
        for v in self.list:
            assert isinstance(v, Gateway)
            if v.get_ip_addr() == ip_addr:
                return v.eth
        return None
class Gateway:
    def __init__(self, eth, ip_addr, mask):
        assert isinstance(eth, str)
        assert isinstance(ip_addr,str)
        assert isinstance(mask, int)
        self.eth = eth
        self.__nw_addr = IPNetwork(ip_addr+'/'+str(mask)).network
        self.__ip_addr = IPAddress(ip_addr)
        self.mask = mask
    def __str__(self):
        return dict({'eth':self.eth,'ip_addr':self.ip_addr})
    def get_nw_addr(self):
        return str(self.__nw_addr)
    def get_ip_addr(self):
        return str(self.__ip_addr)
    def get_eth(self):
        return self.eth


class QsysTest(SimpleSwitch13):
	#動作モード
    #ACTION_MODE = SystemActionMode.quarantine
   
    def __init__(self, *args, **kwargs):
        super(QsysTest, self).__init__(*args, **kwargs)
        self.logger = logging.getLogger()
        self.logger.setLevel(logging.INFO)
        handler = RainbowLoggingHandler(sys.stderr)
        self.logger.addHandler(handler)
        self.datapathes = []    #[[dp,parser],]
        self.cList = ClientList(self.logger)
        self.qsys = Qsys(self.logger, self.cList) #Qsys object
        self.mac_to_port = {}   #{dpid:{addr:in_port}}
        self.mac_to_ipv4 = {}   #{mac:ipv4}
        self.mac_deny_list = {} #{mac:ipv4}到達拒否のClientのリスト
                                #到達拒否のClientで、swに拒否フローを流し込み終わったもの
        self.gateway = GatewayList()#デフォルトゲートウェイ(ハード－コード){ipv4:eth}
        self.monitor_thread = hub.spawn(self.update_mac_deny_list)#
        
        
    #コントローラにSWが接続される
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = Dp_obj(ev.msg)
        self.datapathes.append(dp)
        
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
    def client_regist_port(self, eth, dpid, in_port):
        self.logger.debug("regist_port:eth{} dpid:{} port:{}".format(eth,dpid,in_port))
        if self.cList.check_registed_eth(eth):
            return 
        c = Client(eth=eth,dpid=dpid, port=in_port)
        self.cList.add(c)
    def client_regist_ipv4(self, eth, ipv4):
        mask = 24#今回は決め打ち
        default_route=str(IPNetwork(ipv4+'/'+str(mask))[254])#.254で決め打ち
        if self.cList.get_from_eth(eth):
            c = Client(eth=eth, ip_addr=ipv4, mask=mask,default_route=default_route)
            self.cList.add(c)
        else:
            self.logger.warning("client_regist_ipv4 ERROR. eth NOT registed?")
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
            self.logger.debug("packet-in {}".format(pkt))
        except:
            self.logger.warning("malformed packet")
            return
        eth = pkt.get_protocol(ETHERNET)
        if not eth:
            self.logger.warning("Not Ether type")
            return
        qsys_pkt.set_eth(eth)#qsys_pktにethを登録
        src_eth = eth.src
        dst_eth = eth.dst
        #clientListにクライアントを登録
        self.client_regist_port(src_eth, dpid, in_port)
        #arpパケット
        arp_pkt = pkt.get_protocol(ARP)
        ipv4_pkt = pkt.get_protocol(IPV4)
        if arp_pkt:
            assert isinstance(arp_pkt, ARP)
            qsys_pkt.set_arp(arp_pkt)
            ipv4_src = arp_pkt.src_ip
            self.logger.debug("ipv4_src:{}".format(ipv4_src))
            self.packet_in_arp(src_eth, dst_eth, pkt, arp_pkt,qsys_pkt, dp) 
            return
        elif ipv4_pkt:
            assert isinstance(ipv4_pkt, IPV4)
            qsys_pkt.set_ipv4(ipv4_pkt)
            ipv4_src = ipv4_pkt.src
            self.packet_in_ipv4(src_eth, dst_eth, pkt, ipv4_pkt, qsys_pkt, dp)
            return
        else:
            self.logger.info("Others Pkt:{}".format(msg))
            #IPV6 or others?
            return
    def packet_in_arp(self, src_eth, dst_eth, pkt, arp_pkt, qsys_pkt, dp):
        assert isinstance(src_eth, str)
        assert isinstance(dst_eth, str)
        assert isinstance(pkt, packet.Packet)
        assert isinstance(arp_pkt, ARP)
        assert isinstance(qsys_pkt, QsysDataStruct)
        assert isinstance(dp, Dp_obj)
        src_ip = arp_pkt.src_ip
        dst_ip = arp_pkt.dst_ip
        self.client_regist_ipv4(src_eth,src_ip)
        if src_ip == dst_ip:
            # GARP -> packet forward (normal)
            #TODO
            #output = ofproto.OFPP_NORMAL
            #self.logger.info('Receive GARP from [%s].', src_ip, extra=dpid)
            #self.logger.info('Send GARP (normal).', dpid)
            return
        #gatewayへのarp
        self.logger.debug(dst_ip)
        gw_eth = self.gateway.get_eth(dst_ip)
        gw_ip = self.gateway.get_ip_addr(dst_eth)
        opcode = arp_pkt.opcode
        if gw_eth and (not gw_ip):#ARP
            self.gw_receive_ARP(src_eth, src_ip, gw_eth, dst_ip, opcode, qsys_pkt,dp)
            return
        elif gw_ip and (not gw_eth):#RARP
            self.gw_receive_RARP(src_eth, src_ip, dst_eth, gw_ip, opcode, qsys_pkt,dp)
        else:
            self._packet_out2(dst_eth, pkt, dp)
            return
    def gw_receive_ARP(self, src_eth, src_ip, gw_eth, gw_ip, opcode, qsys_pkt, dp):
        assert isinstance(src_eth,str)
        assert isinstance(src_ip,str)
        assert isinstance(gw_eth,str)
        assert isinstance(gw_ip,str)
        assert isinstance(opcode, int)
        assert isinstance(qsys_pkt,QsysDataStruct)
        assert isinstance(dp, Dp_obj)
        if opcode == arp.ARP_REQUEST:#ARP Request
            self.gw_send_arp(src_eth, src_ip, gw_eth, gw_ip, arp.ARP_REPLY,dp)
            return
        elif opcode == arp.ARP_REPLY:#ARP_Reply
            self.logger.warning("不正なARPパケット?:{}".format(arp_pkt))
            return#TODO
        else:
            self.logger.warning("不正なarpのopcode?:{}".format(arp_pkt))
            return
    def gw_receive_RARP(self, src_eth, src_ip, gw_eth, gw_ip, opcode, qsys_pkt, dp):
        assert isinstance(src_eth,str)
        assert isinstance(src_ip,str)
        assert isinstance(gw_eth,str)
        assert isinstance(gw_ip,str)
        assert isinstance(qsys_pkt,QsysDataStruct)
        assert isinstance(dp, Dp_obj)
        if opcode == arp.ARP_REV_REQUEST:#RARP_REQUEST
            self.gw_send_arp(src_eth, src_ip, gw_eth, gw_ip, arp.ARP_REV_REPLY,dp)
        elif opcode == arp.ARP_REV_REPLY:
            self.logger.warning("不正なRARPパケット?:{}".format(arp_pkt))
        else:
            self.logger.warning("不正なarpのopcode?:{}".format(arp_pkt))
            return
    def gw_send_arp(self, src_eth, src_ip, gw_eth, gw_ip, opcode, dp):
        assert isinstance(src_eth, str)
        assert isinstance(src_ip, str)
        assert isinstance(gw_eth, str)
        assert isinstance(gw_ip, str)
        assert isinstance(opcode, int)
        assert isinstance(dp, Dp_obj)
        if opcode == arp.ARP_REQUEST:#ARP Request
            pass
        elif opcode == arp.ARP_REPLY:#ARP/RARP Reply
            target_eth = src_eth
            target_ip = src_ip
            e = ETHERNET(target_eth, gw_eth , ether_types.ETH_TYPE_ARP)
            a = ARP(1, 0x0800, 6, 4, opcode, gw_eth, gw_ip, target_eth, target_ip)
            p = packet.Packet()
            p.add_protocol(e)
            p.add_protocol(a)
            p.serialize()
            self.logger.info("gw_arp:{}".format(p))
            self._packet_out2(src_eth, p, dp)
            return 
        elif opcode == arp.ARP_REV_REPLY:
            target_eth = src_eth
            target_ip = src_ip
            e = ETHERNET(target_eth, gw_eth , ether_types.ETH_TYPE_ARP)
            a = ARP(1, 0x0800, 6, 4, opcode, srcMac, srcIp, target_eth, target_ip)
            p = packet.Packet()
            p.add_protocol(e)
            p.add_protocol(a)
            p.serialize()
            self._packet_out2(src_eth, p, dp)
            return 
        elif opcode == arp.ARP_REV_REQUEST:
            pass
        else:
            pass

    def packet_in_ipv4(self, src_eth, dst_eth, pkt, ipv4_pkt, qsys_pkt, dp):
        assert isinstance(src_eth, str)
        assert isinstance(dst_eth, str)
        assert isinstance(pkt, packet.Packet)
        assert isinstance(ipv4_pkt, IPV4)
        assert isinstance(qsys_pkt, QsysDataStruct)
        assert isinstance(dp, Dp_obj)
        self.logger.info("ipv4")
        src_ip = ipv4_pkt.src
        dst_ip = ipv4_pkt.dst
        icmp_pkt = pkt.get_protocol(ICMP)
        tcp_pkt = pkt.get_protocol(TCP)
        udp_pkt = pkt.get_protocol(UDP)
        if icmp_pkt:
            assert isinstance(icmp_pkt, ICMP)
            ttl = ipv4_pkt.ttl
            self.packet_in_icmp(src_eth, dst_eth, src_ip, dst_ip, ttl, pkt, qsys_pkt, dp)
            return
        elif tcp_pkt:
            assert isinstance(tcp_pkt, TCP)
            #self._packet_in_tcp()
            return
        
        elif udp_pkt:
            assert isinstance(udp_pkt, UDP)
            #self.packet_in_udp()
            return
        else:
            self.logger.warning("L3 Others:{}".format(pkt))
            return

    def packet_in_icmp(self, src_eth, dst_eth, src_ip, dst_ip, ttl, pkt, qsys_pkt, dp, ):
        assert isinstance(src_eth, str)
        assert isinstance(dst_eth, str)
        assert isinstance(src_ip, str)
        assert isinstance(dst_ip, str)
        assert isinstance(ttl, int)
        assert isinstance(pkt, packet.Packet)
        assert isinstance(qsys_pkt, QsysDataStruct)
        assert isinstance(dp, Dp_obj)
        self.logger.info("icmp")
        self.logger.info(pkt)
        if self.gateway.get_eth(dst_ip):#gwへのicmp
            self.gw_reply_icmp(src_eth, src_ip, 
                               self.gateway.get_eth(dst_ip), dst_ip, 
                               pkt.get_protocol(ICMP),ttl, dp)
            return
        elif self.gateway.get_ip_addr(dst_eth):#別NWへのICMP
            self.gw_foward_icmp()
            return
        else:#同一NWへのICMP or 不正なICMP？
            self.logger.debug("Same NW icmp")
            self._packet_out2(dst_eth, pkt, dp)
            return

    def gw_reply_icmp(self, src_eth, src_ip, gw_eth, gw_ip, icmp_pkt, ttl, dp):
        assert isinstance(src_eth, str)
        assert isinstance(src_ip,  str)
        assert isinstance(gw_eth, str)
        assert isinstance(gw_ip, str)
        assert isinstance(icmp_pkt, ICMP)
        assert isinstance(ttl, int)
        assert isinstance(dp, Dp_obj)
        self.logger.info("gw_icmp")
        if icmp_pkt.type != icmp.ICMP_ECHO_REQUEST:#ICMP ECHO REQUESTではない
            return
        p = packet.Packet()
        p.add_protocol(ETHERNET(ethertype=ether_types.ETH_TYPE_IP,
                                           dst=src_eth,
                                           src=gw_eth))
        p.add_protocol(IPV4(dst=src_ip, src=gw_ip, ttl=ttl-1))
        p.add_protocol(ICMP(type_=icmp.ICMP_ECHO_REPLY,
                                   code=icmp.ICMP_ECHO_REPLY_CODE,
                                   csum=0,
                                   data=icmp_pkt.data))
        p.serialize()
        self._packet_out2(src_eth, p, dp)
    def gw_foward_icmp(self):
        pass

    def packet_in_tcp(self, src_eth, dst_eth, src_ip, dst_ip, pkt, tcp_pkt, qsys_pkt, dp):
        assert isinstance(src_eth, str)
        assert isinstance(dst_eth, str)
        assert isinstance(src_ip, str)
        assert isinstance(dst_ip, str)
        assert isinstance(pkt, packet.Packet)
        assert isinstance(tcp_pkt, TCP)
        assert isinstance(qsys_pkt, QsysDataStruct)
        assert isinstance(dp, Dp_obj)

        #以下dpktで処理
        f = BytesIO()
        pcap = RyuLibPcapWriter(f).write_pkt(pkt.data)#pcaplib.Writer
        data = dpkt.pcap.Reader(BytesIO(f.getvalue()))
        f.close()
        for t,k in data:
                eth = dpkt.ethernet.Ethernet(k)
                assert isinstance(eth, dpkt.ethernet.Ethernet)
                ip = eth.data
                assert isinstance(ip, dpkt.ip.IP)
                tcp = ip.data
                if not type(tcp) == dpkt.tcp.TCP:
                    #dpktで読み取れないTCPのpkt
                    return
                assert isinstance(tcp, dpkt.tcp.TCP)
                sport = tcp.sport
                assert isinstance(sport, int)
                dport = tcp.dport
                assert isinstance(dport, int)
                if dport == 80 or sport == 80:
                    self.packet_in_http(src_eth, src_ip, dst_ip, sport, dport, tcp.data)
                else:
                    return
    def packet_in_http(self, src_eth, src_ip, dst_ip, sport, dport, tcp_payload):
        assert isinstance(sport, int)
        assert isinstance(dport, int)
        assert isinstance(tcp_payload, bytes)
        payload = tcp_payload
        if len(payload) <= 0:
            return
        try:
            http = dpkt.http.Request(payload.decode('utf-8'))
            self.logger.info("http/req(header):{}".format(http.headers))
            self.logger.info("http(method):{}".format(http.method))
            self.logger.info("http(data):{}".format(http.data))
            _http = dpkt.http.Response(payload.decode('utf-8'))
            self.logger.info("http/res(header):{}".format(_http.headers))
            self.logger.info("http(body):{}".format(_http.body))
            self.logger.info("http(data):{}".format(_http.data))
        except:
            pass
        self._send_qsys(dst_eth, pkt, qsys_pkt, dp)
        return

    def _packet_in_udp(self, msg, pkt, qsys_pkt, dp, udp):
        self.send_qsys(msg, qsys_pkt, dp)
        pass
    def _send_qsys(self,dst_eth, pkt, qsys_pkt, dp):
        assert isinstance(dst_eth, str)
        assert isinstance(pkt, packet.Packet)
        assert isinstance(qsys_pkt, QsysDataStruct)
        assert isinstance(dp, Dp_obj)
        result = self.qsys.send(qsys_pkt)
        if True == result:
            self.packet_out(dst_eth, pkt, dp)
            return
        else:#Drop Packet
            self.logger.info('Drop:{}'.format(qsys_pkt))
            return 
    def send_qsys(self, msg, qsys_pkt,  dp):
        self.logger.info("send_qsys{}".format(qsys_pkt))
        result = self.qsys.send(qsys_pkt)
        if True == result:
            self._packet_out2(msg, qsys_pkt, dp)
            return
        else:#Drop Packet
            self.logger.info('Drop:{}'.format(qsys_pkt))
            return 

    def _packet_out2(self, dst_eth, pkt, dp):
        self.logger.debug("pkt:{}".format(pkt))
        client = self.cList.get_from_eth(dst_eth)
        #Transport to dst
        out_dpid = None
        out_port = None
        if isinstance(client, Client):
            if client.dpid and client.port:
                out_dpid = client.dpid
                out_port = client.port
        else:
            #フラッディング
            out_dpid = None
            out_port = ofproto_v1_3.OFPP_FLOOD
        actions = None
        for obj in self.datapathes:
            assert isinstance(obj, Dp_obj)
            self.logger.debug("obj.dpid:{}".format(obj.dpid))
            self.logger.debug("out_dpid:{}".format(out_dpid))
            if out_dpid == obj.dpid:
                datapath = obj.datapath
                actions = [obj.parser.OFPActionOutput(out_port)]
                out = obj.parser.OFPPacketOut(
                    datapath=obj.datapath, buffer_id=ofproto_v1_3.OFP_NO_BUFFER, in_port=ofproto_v1_3.OFPP_CONTROLLER,
                    actions=actions, data=pkt.data)
                datapath.send_msg(out)
                self.logger.info("send!:{}".format(pkt))
                return
        datapath = dp.datapath
        actions = [dp.parser.OFPActionOutput(out_port, 0)]
        out = dp.parser.OFPPacketOut(
            datapath=dp.datapath, buffer_id=ofproto_v1_3.OFP_NO_BUFFER, in_port=ofproto_v1_3.OFPP_CONTROLLER,
            actions=actions, data=pkt.data)
        datapath.send_msg(out)
        self.logger.info("send!:{}".format(pkt))
        return
    
    def update_mac_deny_list(self):
        """低信頼度のClientをpacket_inしないようswitchにflowを流し込む。
        スレッドとして立ち上げ定期的に実行する"""
        #TODO:そのうちqsysからのイベントで呼び出せるようにしたい
        while True:
            lst = self.cList.get_all()
            for c in lst:
                eth = c.get_eth()
                ip = c.get_ip()
                level = c.get_level()
                eval = c.get_eval()
                self.logger.debug("IP:{}".format(ip))
                self.logger.debug("Level:{}".format(level))
                if QsysRelEval.LOW == eval:
                    if not eth in self.mac_deny_list:
                        for dp in self.datapathes:#dp[0]:dp,dp[1]:parser
                            match = dp.parser.OFPMatch(eth_src=eth)
                            actions = []#Drop
                            self.add_flow(dp.datapath, 10,match, actions)
                        self.mac_deny_list.update({eth:ip})#拒否済に追加
                elif QsysRelEval.UNKNOWN == eval:
                    #TODO:登録されていないClientを参照した際の例外処理
                    pass
            c = self.cList.get_from_ipv4('10.0.0.1')#テストコード。10.0.0.1の信頼度を1(< LOW)に
            if c:
                c.update_reliability_level(1)
            hub.sleep(5)

class RyuLibPcapWriter(pcaplib.Writer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def __del__(self):
        pass