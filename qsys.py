import json
import logging

import ryu

from ryu.base import app_manager
import ryu.controller.dpset
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
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

class DbAccess:
    def __init__(self):
        dbname = 'black_client.sqlite3'
        conn = sqlite3.connect(dbname)
        self.c = conn.cursor()
    def get_list(self):
        return self.c.execute("SELECT * FROM \'access_refused_ip\';")
class Qsys:
    def __init__(self, *args, **kwargs):
        print(DbAccess().get_list())
        True
    def send(self, pkt_dict):
        return True