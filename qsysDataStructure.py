from ryu.lib.packet import *
#from ryu.ofproto.ofproto_v1_3_parser import OFPMatch
from ryu.controller  import ofp_event, event
from ryu.base import app_manager
from ryu.controller import ofp_event

class PacketDataStructure:
    """
    使用するパケットのデータ
    """
    #送信元
    #スイッチの物理ポート
    in_port
    #MACアドレス
    mac_src
    #IPv4アドレス
    ipv4_src
    #プロトコルタイプ

    #データパス(OFC-OFSW間の経路)
    datapath
    #データパスID(OF-SWのID)
    dpid

    ofproto
    parser
    total_len
    data

    def packet_parse(self, ev):
        msg = ev.msg
        self.datapath = msg.datapath
        self.ofproto = self.datapath.ofproto
        self.parser = self.datapath.ofproto_parser
        self.dpid = self.datapath.id
        #スイッチの物理ポート
        self.in_port = msg.match['in_port']  
        #MACアドレス
        self.mac_src = msg.match['eth_src']
        #IPv4アドレス
        self.ipv4_src = msg.match['ipv4_src']
        """
            match	ryu.ofproto.ofproto_v1_3_parser.OFPMatchクラスのインスタンスで、受信パケットのメタ情報が設定されています。
            data	受信パケット自体を示すバイナリデータです。
            total_len	受信パケットのデータ長です。
            buffer_id	受信パケットがOpenFlowスイッチ上でバッファされている場合、そのIDが示されます。バッファされていない場合は、ryu.ofproto.ofproto_v1_3.OFP_NO_BUFFERがセットされます。
        """
        self.total_len = msg.total_len
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dst = eth.dst
        src = eth.src
        self.mac_to_port.setdefault(dpid, {})
        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)