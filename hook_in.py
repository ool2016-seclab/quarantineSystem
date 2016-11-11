#-*- coding: utf-8 -*-
import json
import enum 
from ryu.app.simple_switch_13 import SimpleSwitch13
from ryu.controller  import ofp_event, event
from ryu.controller.handler import set_ev_cls,MAIN_DISPATCHER,CONFIG_DISPATCHER
from ryu.ofproto.ofproto_v1_3 import *
from ryu.ofproto.ofproto_v1_3_parser import OFPMatch
from ryu.ofproto.ofproto_parser import *
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ipv4,arp
from ryu.controller import dpset
from qsys import Qsys
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
        allowTransportFlag = False
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        #送信元MACと送信元SWのポートの対応関係を記録
        self.mac_to_port.setdefault(dpid, {})
        pkt = packet.Packet(msg.data)
        if self.__DEBUG_MODE__:
            self.logger.info("packet-in {}".format(pkt))
        _eth = pkt.get_protocol(ethernet.ethernet)
        if not _eth:
            self.logger.info("Not Ether type")
            return
        #スイッチのポート
        in_port = msg.match['in_port'] 
        #[swのid][MACAddr]のテーブルにSwitch input portを登録
        self.mac_to_port[dpid][_eth.src] = in_port
#        pkt_head = packet.packet_base.PacketBase(msg.data)
#       pkt_head.get_packet_type()
        _ipv4 = pkt.get_protocol(ipv4.ipv4)
        if not _ipv4:
            _arp = pkt.get_protocol(arp.arp)
        
        pkt_dict = {
            'src':_eth.src,
            'dst':_eth.dst,
            'data':msg.data,
            }
        #pkt_json = json.dumps(pkt_dict, sort_keys=True)
        
        result = self.send_qsys(pkt_dict)#通信許可T/Fを返す
        if result == False:
            self.logger.info('Drop:{}'.format(pkt_dict))
            return
        #Transport to dst
        #print('Transport:{}⇢{}'.format(packet.ipv4_src))
        if self.__DEBUG_MODE__:
            self.logger.info('json:{}'.format(json.dumps(ev.msg.to_jsondict(), ensure_ascii=True,
                                  indent=3, sort_keys=True)))
        #該当するSWの中にMacAddrがあるか？
        if _eth.dst in self.mac_to_port[dpid]:
            #Switch output portをテーブルから指定
            out_port = self.mac_to_port[dpid][_eth.dst]
        else:
            #フラッディング
            out_port = ofproto.OFPP_FLOOD
        actions = [parser.OFPActionOutput(out_port)]
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=msg.data)
        datapath.send_msg(out)

    def send_qsys(self, pkt_dict):
        self.logger.info("Qsys_in{}".format(pkt_dict))
        qsys = Qsys()
        res = qsys.send(pkt_dict)
        if res == True:
            return True
        else:
            return False
