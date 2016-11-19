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
import netaddr
from ryu.lib.packet import *
import types
from builtins import hasattr

ETHERNET = ethernet.ethernet
VLAN = vlan.vlan
IPV4 = ipv4.ipv4
ARP = arp.arp
ICMP = icmp.icmp
TCP = tcp.tcp
UDP = udp.udp
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
    def __init__(self):
       pass 
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
    def set_data(self,data):
        assert isinstance(data, str)
        """
        dataに値をsetする。
        data -- bytes
        """
        self.data = data
    def ready(self):
        """hasAttr? eth & ipv4Address
        return bool"""
        if self.get_ethObj() and self.get_ipv4Addr_src() and self.get_ipv4Addr_dst():
            return True
        else:
            return False
    def get_ethObj(self):
        if hasattr(srlf,"eth"):
            return self.eth
        return None
    def get_ethAddr(self):
        """return [src(str),dst(str)]"""
        return [self.get_ethAddr_src(), self.get_ethAddr_dst()]
    def get_ethAddr_src(self):
        if hasattr(srlf,"eth_src"):
            return self.eth_src
        return None
    def get_ethAddr_dst(self):
        if hasattr(srlf,"eth_dst"):
            return self.eth_dst
        return None
    def get_arpObj(self):
        """return object(ryu.lib.packet.arp.arp)"""
        if hasattr(self, "arp"):
            return self.arp
        else:
            return None
    def get_ipv4Obj(self):
        """return object(ryu.lib.packet.ipv4.ipv4)"""
        if hasattr(self,"ipv4"):
            return self.ipv4
        else:
            return None
    def get_ipv4Addr(self):
        """return [src(str), dst(str)]"""
        return [self.get_ipv4Addr_src(), self.get_ipv4Addr_dst()]
    def get_ipv4Addr_src(self):
        if hasattr(self,"ipv4_src"):
            return self.ipv4_src
        else:
            return None
    def get_ipv4Addr_dst(self):
        if hasattr(self,"ipv4_dst"):
            return self.ipv4_dst
        else:
            return None
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
    L_MAX = 10    #信頼度レベル上限
    HIGH = 8  #信頼度評価:HIGH　     この値以上が高信頼
    DEFAULT = 5#Clientの初期信頼度。 この値の間が注意
    LOW = 2   #信頼度評価:LOW        この値以下が低信頼
    MIN = 0     #信頼度レベル下限
    
    UNKNOWN = -1
class QsysRelEval:
    """Qsysで使用する信頼度評価の定義。
    識別用で中の値は関係ない。
    """
    HIGH = 3
    MID = 2
    LOW = 1
    UNKNOWN = -1
    
class Qsys:
    def __init__(self, *args, **kwargs):
        #print(DbAccess().get_list())
        self.reliability_level = {}#信頼度レベル{ip:level}
    def send(self, qsys_pkt):
        return True
    def update_reliability_level(self, ipv4, num):
        if self.is_range_of_reliability(num):
            self.reliability_level[ipv4] = num
    def regist_client(self,qsys_pkt):
        """Clientの登録
        はじめて通信を行ったClientを登録する。
        """
        srcip = qsys_pkt.get_ipv4Addr_src()
        if srcip:
            if not srcip in self.reliability_level:#Not exist
                self.reliability_level.update({srcip:QsysRelLevel.DEFAULT})#regist client
                return True
        else:
            return False
            #TODO:Clientの登録処理
    def get_reliability_level(self,ipv4):
        """Clientの信頼度レベルを返す。"""
        if ipv4 in self.reliability_level:
            level = self.reliability_level[ipv4]
            return level
        else:
            return QsysRelLevel.UNKNOWN
    def get_reliability_eval(self, ipv4):
        """Clientの信頼度評価を返す。
        HIGH:高信頼。チェックをスキップして到達可能。(学習のみ)
        MID:注意。毎回通信をチェックして到達可否を判断
        LOW:低信頼。到達を恒常的にブロック(学習するかは未定)
        UNKNOWN:登録されていない
        """
        level = self.get_reliability_level(ipv4)
        if QsysRelLevel.UNKNOWN == level:
            return QsysRelEval.UNKNOWN
        else:
            if level >= QsysRelLevel.HIGH:
                return QsysRelEval.HIGH
            elif level <= QsysRelLevel.LOW:
                return QsysRelEval.LOW
            return QsysRelEval.MID
    def is_range_of_reliability(self, level):
        if level <= QsysRelLevel.L_MAX and\
           level >= QsysRelLevel.MIN:
            return True
        else:
            return False