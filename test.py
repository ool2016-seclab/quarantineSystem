import enum
import ryu.app.simple_switch_13
from ryu.controller  import ofp_event, event, ev
from ryu.controller.handler import set_ev_cls,MAIN_DISPATCHER,CONFIG_DISPATCHER
from ryu.ofproto.ofproto_v1_3 import *
from ryu.ofproto.ofproto_v1_3_parser import OFPMatch
from ryu.ofproto.ofproto_parser import *
from ryu.lib.packet import packet
from qsysDataStructure import *
from ryu.controller import dpset
from builtins import print

__DEBUG_MODE__ = 0#1:on,0:off
class SystemActionMode(enum):
    """
    あとでモード実装するはず？
    """
    learn = 0
    quarantine = 1
class Test(ryu.app.simple_switch_13):
    
    #動作モード
    ACTION_MODE = SystemActionMode.quarantine

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)

    #packet_inハンドラ(override)
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        allowTransportFlag = False
        packet = PacketDataStructure 
        packet.packet_parse(ev)
     
        allowTransportFlag = end_qsys(packet);#通信許可T/Fを返す
        if not(allowTransportFlag):#False
            print('Drop:{}⇢{}'.format(packet.ipv4['src']))
            return
        #Transport to dst
        print('Transport:{}⇢{}'.format(packet.ipv4['src']))
        src = packet.mac_src
        dpid = packet.dpid
        #[swのid][MACAddr]のテーブルにSwitch input portを登録
        self.mac_to_port[dpid][src] = in_port
        #該当するSWの中にMacAddrがあるか？
        if dst in self.mac_to_port[dpid]:
            #Switch output portをテーブルから指定
            out_port = self.mac_to_port[dpid][dst]
        else:
            #フラッディング
            out_port = ofproto.OFPP_FLOOD
        actions = [parser.OFPActionOutput(out_port)]

    def send_qsys(self, packet):
        return True#pktの到達許可