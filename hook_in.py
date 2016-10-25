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
"""__DEBUG_MODE__ = 0#1:on,0:off
class SystemActionModei(enum.Enum):
   # あとでモード実装するはず？
learn = 0
quarantine = 1
"""

class QsysTest(SimpleSwitch13):
	#動作モード
    #ACTION_MODE = SystemActionMode.quarantine

    def __init__(self, *args, **kwargs):
        super(QsysTest, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        allowTransportFlag = False
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        self.mac_to_port.setdefault(dpid, {})
        
        pkt = packet.Packet(msg.data)
        
        self.logger.info("packet-in {}".format(pkt))
        
        _eth = pkt.get_protocol(ethernet.ethernet)
        if not _eth:
            self.logger.info("Not Ether type")
            return
        _arp = pkt.get_protocol(arp.arp)
        if not _arp:
            self.logger.info("Not ARP type")
        else:
            self.logger.info("Arp:{}".format(_arp))
        _ipv4 = pkt.get_protocol(ipv4.ipv4)
        if not _ipv4:
            self.logger.info("Not IPv4")
        else:
            self.logger.info("IPv4:{}".format(_ipv4))
        #スイッチのポート
        in_port = msg.match['in_port'] 
        #MACアドレス
        self.logger.info("Eth:{}".format(_eth))
        #IPv4アドレス
        #ipv4_src = ipv4_addr[0].src
        allowTransportFlag = True
        pkt_json = json.dumps(ev.msg.to_jsondict(), ensure_ascii=True,
                                  indent=3, sort_keys=True)
        allowTransportFlag = self.send_qsys(pkt_json);#通信許可T/Fを返す
        if not(allowTransportFlag):#False
            logger,info('Drop:{}'.format(pkt_json))
            return
        #Transport to dst
        #print('Transport:{}⇢{}'.format(packet.ipv4_src))
        src = _eth.src
        dst = _eth.dst
        self.logger.info("in_port:{}".format(in_port))
        self.logger.info("dpid:{}".format(dpid))
        self.logger.info("mac_arc:{}".format(src))
        self.logger.info("mac_to_port:{}".format(self.mac_to_port))
        self.logger.info('json:{}'.format(json.dumps(ev.msg.to_jsondict(), ensure_ascii=True,
                                  indent=3, sort_keys=True)))
        #[swのid][MACAddr]のテーブルにSwitch input portを登録
        self.mac_to_port[dpid][_eth.src] = in_port
        #該当するSWの中にMacAddrがあるか？
        if _eth.src in self.mac_to_port[dpid]:
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

    def send_qsys(self, pkt_json):
        self.logger.info("Qsys_in{}".format(json))
        return True#pktの到達許可


"""if __name__ == '__main__':
    import sys
    sys.argv.append(__name__)
    from ryu.cmd import manager
    manager.main()
"""
