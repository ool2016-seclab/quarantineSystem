import json
import logging

import ryu

from ryu.base import app_manager
import ryu.controller.dpset
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import *
from ryu.lib import hub
from webob import Response
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.topology import switches
from ryu.controller.ofp_event import *
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.lib import dpid as dpid_lib
from ryu.controller import dpset
from ryu.topology import switches
import sqlite3
from netaddr import *
from ryu.lib.packet import *
import types
from builtins import hasattr, staticmethod
import time

ETHERNET = ethernet.ethernet
VLAN = vlan.vlan
IPV4 = ipv4.ipv4
ARP = arp.arp
ICMP = icmp.icmp
TCP = tcp.tcp
UDP = udp.udp
"""
class subnetList:
    def __init__(self, **kwargs):
        self.netlist = {}#{nwAddr/mask:ClientList}
    def setSubnet(self,nwAddr, mask=32, clientList=ClientList()):
        subnet = self.makeSubnetKey(nwAddr,mask)
        self.netlist.setdefault(subnet,clientList)
    def delSubnet(self, netAddr, mask=32):
        subnet = self.makeSubnetKey(nwAddr,mask)
        if subnet in self.netlist:
            self.netlist.pop(subnet)
    def getClientListObject(self, nwAddr, mask=32):
        subnet = makeSubnetKey(nwAddr, mask)
        if subnet in self.netlist:
            return self.netlist[subnet]
    def makeSubnetKey(self, nwAddr, mask=32):
        return nwAddr+'/'+mask
"""
class ClientList:
    def __init__(self, logger):
        self.list = []#[Client_object,]
        self.logger = logger
        #hub.spawn(self.check_client_expire())
    def add(self, client):
        assert isinstance(client, Client)
        eth = client.eth
        if self.check_registed_eth(eth):
            pass
        #    self.change(eth, client)
        else:
            self.list.append(client)
    def check_registed_eth(self, eth):
        for c in self.list:
            if c.eth == eth:
                return True
        return False
    def change(self, eth, client):
        assert isinstance(client, Client)
        self.logger.info("client data changed")
        for i, c in enumerate(self.list):
            if c.eth == eth:
                self.list[i] = client
    def delete(self, eth):
        for i, c in enumerate(self.list):
            if c.eth == eth:
                pop = self.list.pop(i)
                self.logger.debug(pop)
        return
    def get_all(self):
        return self.list
    def get_from_eth(self, eth):
        for c in self.list:
            if c.eth == eth:
                return c
        return None
    def get_from_ipv4(self, ip_addr):
        for c in self.list:
            if c.ip_addr == ip_addr:
                return c
        return None
    def check_client_expire(self):
    #Client.lastUpdateの情報を基に一定時間経過後に情報を削除
        pass


class Client:
    def __init__(self, eth, ip_addr=None, mask=None , default_route=None, dpid=None, port=None):
        assert isinstance(eth, str)
        self.eth = eth
        self.nw_addr = None
        self.ip_addr = None
        self.mask = None
        self.default_route = None
        self.dpid=None
        self.port=None
        self.lastUpdate = None
        if ip_addr and mask:
            self.set_ip_addr(ip_addr,mask)
        if default_route:
            self.set_default_route(default_route)
        if dpid and port:
            self.set_dpid(dpid, port)
        self.level = QsysRelLevel().DEFAULT
        self.touch()
    def set_ip_addr(self, ip_addr, mask, default_route=None):
        assert isinstance(ip_addr, str)
        assert isinstance(mask, int)
        self.nw_addr = IPNetwork(ip_addr+'/'+str(mask)).network
        self.ip_addr = IPAddress(ip_addr)
        assert isinstance(self.nw_addr,IPAddress)
        assert isinstance(self.ip_addr, IPAddress)
        self.mask = mask 
        if default_route:
            self.set_default_route(default_route)
        self.touch()
    def set_default_route(self, default_route):
        assert isinstance(default_route, str)
        self.default_route = default_route
        self.touch()
    def set_dpid(self, dpid, port):
        assert isinstance(dpid, int)
        assert isinstance(port, int)
        self.dpid = dpid
        self.port = port
        self.touch()
    def touch(self):
        self.lastUpdate = time.time()
    def __str__(self):
        return [self.eth, self.nw_addr, self.ip_addr, self.mask, self.default_route, self.level]
    def get_eth(self):
        return self.eth
    def get_ip(self):
        return self.ip_addr
    def get_mask(self):
        return self.mask
    def get_nw_addr(self):
        return self.nw_addr
    def get_level(self):
        return self.level
    def get_eval(self):
        return QsysRelEval.get_reliability_eval(self, self.level)
    def update_reliability_level(self, level):
        self.level = level
        return

class QsysDataStruct:
    """
    Qsysで使用するデータ構造を定義するクラス。
    ============== ==================== =====================
    Attribute      Description          Example
    ============== ==================== =====================
    eth_src        送信元MACアドレス    '08:60:6e:7f:74:e7'
    eth_dst        送信先MACアドレス    'ff:ff:ff:ff:ff:ff'
    ipv4_src       送信元IPv4アドレス   '10.0.0.1'
    ipv4_dst       送信先IPv4アドレス   '10.0.0.2'
    ============== ==================== =====================
    """
    def __init__(self, logger):
        self.logger = logger
        self.eth = None
        self.eth_src = None
        self.eth_dst = None
        self.ipv4 = None
        self.ipv4_src = None
        self.ipv4_dst = None
        self.tcp = None
        self.udp = None
        self.icmp = None
        self.icmp_code = None
        self.icmp_data = None
        self.http = None

    def set_eth(self, eth):
        """
        eth_src/dstに値をsetする。
        eth -- ryu.lib.packet.ethernetオブジェクト
        """
        assert isinstance(eth, ETHERNET)
        self.eth_src = eth.src
        self.eth_dst = eth.dst
        self.eth = eth
    def set_arp(self, arp):
        """
        ipv4_src/dstに値をsetする。
        arp -- ryu.lib.packet.arpオブジェクト
        """
        assert isinstance(arp, ARP)
        self.ipv4_src = arp.src_ip
        self.ipv4_dst = arp.dst_ip
        self.arp = arp
    def set_ipv4(self,ipv4):
        """
        ipv4_src/dstに値をsetする。
        ipv4 -- ryu.lib.packet.ipv4オブジェクト
        """
        assert isinstance(ipv4, IPV4)
        self.ipv4_src = ipv4.src
        self.ipv4_dst = ipv4.dst
        self.ipv4 = ipv4
    def set_tcp(self, tcp_pkt):
        self.tcp = tcp_pkt
    def set_upd(self, udp_pkt):
        self.udp = udp_pkt
    def set_icmp(self, icmp_pkt):
        self.icmp = icmp_pkt
        self.icmp_code = icmp_pkt.code
        self.icmp_data = icmp_pkt.data
    def set_http(self, http_pkt):
        self.http = http_pkt
    def get_ethObj(self):
        return self.eth
        return None
    def get_ethAddr(self):
        """return [src(str),dst(str)]"""
        return [self.get_ethAddr_src(), self.get_ethAddr_dst()]
    def get_ethAddr_src(self):
        """return eth_src"""
        return self.eth_src
        return None
    def get_ethAddr_dst(self):
        """return eth_src"""
        return self.eth_dst
    def get_arpObj(self):
        """return object(ryu.lib.packet.arp.arp)"""
        return self.arp
    def get_ipv4Obj(self):
        """return object(ryu.lib.packet.ipv4.ipv4)"""
        return self.ipv4
    def get_ipv4Addr(self):
        """return [src(str), dst(str)]"""
        return [self.get_ipv4Addr_src(), self.get_ipv4Addr_dst()]
    def get_ipv4Addr_src(self):
        """return ipv4_src"""
        return self.ipv4_src
    def get_ipv4Addr_dst(self):
        """return eth_dst"""
        return self.ipv4_dst
    def get_tcpObj(self):
        return self.tcp
    def get_udpObj(self):
        return self.udp
    def get_icmpObj(self):
        return self.icmp
    def get_icmpData(self):
        return self.icmp_data
    def get_http(self):
        return self.http

class DbAccess:
    def __init__(self):
        dbname = 'black_client.sqlite3'

        conn = sqlite3.connect(dbname)
        self.c = conn.cursor()
    def get_list(self):
        response = self.c.execute("SELECT ip FROM \'access_refused_ip\' WHERE deny=1;")
        return "DB_TEST"
class QsysRelLevel:
    """信頼度レベルと信頼度評価閾値の定義
    """
    #信頼度レベル
    MAX = 10    #信頼度レベル上限
    HIGH = 8  #信頼度評価:HIGH　     この値以上が高信頼
    DEFAULT = 5#Clientの初期信頼度。 この値の間が注意
    LOW = 2   #信頼度評価:LOW        この値以下が低信頼
    MIN = 0     #信頼度レベル下限
    UNKNOWN = -1

    @staticmethod
    def is_range_of_reliability(self, level):
        if level <= QsysRelLevel.MAX and\
            level >= QsysRelLevel.MIN:
            return True
        else:
            return False
class QsysRelEval:
    """Qsysで使用する信頼度評価の定義。
    識別用で中の値は関係ない。
    """
    HIGH = 3
    MID = 2
    LOW = 1
    UNKNOWN = -1
    @staticmethod
    def get_reliability_eval(self, level):
        """Clientの信頼度評価を返す。
        HIGH:高信頼。チェックをスキップして到達可能。(学習のみ)
        MID:注意。毎回通信をチェックして到達可否を判断
        LOW:低信頼。到達を恒常的にブロック(学習するかは未定)
        UNKNOWN:登録されていない
        """
        if QsysRelLevel.UNKNOWN == level:
            return QsysRelEval.UNKNOWN
        else:
            if level >= QsysRelLevel.HIGH:
                return QsysRelEval.HIGH
            elif level <= QsysRelLevel.LOW:
                return QsysRelEval.LOW
            return QsysRelEval.MID
class Qsys:
    """評価システム。
    =================  ==================== =====================
    Attribute           Description          Example
    =================  ==================== =====================
    reliability_level  Clientの信頼度レベル {'10.0.0.1' : 5}
    =================  ==================== =====================
"""
    def __init__(self, logger, clientList, *args, **kwargs):
        self.logger = logger
        self.cList = clientList
        #print(DbAccess().get_list())
        self.reliability_level = {}#信頼度レベル{ip:level}
    def send(self, qsys_pkt):
        #self.regist_client(qsys_pkt)
        #if QsysRelEval.LOW == self.get_reliability_eval(qsys_pkt.get_ipv4Addr_src):
        #    return False
        #else:
        #    return True
        return True