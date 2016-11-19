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
    def __init__(self):
       pass 
    def set_eth(self, eth):
        assert isinstance(eth, ETHERNET)
        self.eth = eth
    def set_arp(self, arp):
        assert isinstance(arp, ARP)
        self.arp = arp
    def set_ipv4(self,ipv4):
        assert isinstance(ipv4, IPV4)
        self.ipv4 = ipv4
    def set_data(self,data):
        assert isinstance(data, str)
        self.data = data
    def ready(self):
        if self.eth and (self.arp or self.ipv4):
            return True
        else:
            return False
    def get_eth(self):
        if self.eth:
            return self.eth
        return None
    def get_ipv4_src(self):
        if hasattr(self,"arp"):
            return self.arp.src_ip
        elif hasattr(self, "ipv4"):
            return self.ipv4.src
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
        srcip = qsys_pkt.get_ipv4_src()
        if srcip:
            if not srcip in self.reliability_level:#Not exist
                self.reliability_level.update({srcip:QsysRelLevel.DEFAULT})#regist client
            #TODO:Clientの登録処理
    def get_reliability_level(self,ipv4):
        """Clientの信頼度レベルを返す。"""
        level = self.reliability_level[ipv4]
        if level:
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