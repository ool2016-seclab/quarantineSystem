# coding: utf-8
from sklearn.covariance import EmpiricalCovariance

from collections import (
    Counter,
    defaultdict,
)
import ipaddress

DEFAULT_RELIABILITY = 0.5
DEFAULT_BLOCK = 0.3
DEFAULT_THRESH = 4.0


def _parse_ip(ip):
    """
    :type ip: str | ipaddress.IPv4Address | ipaddress.IPv6Address
    :rtype: ipaddress.IPv4Address | ipaddress.IPv6Address
    """
    if isinstance(ip, str):
        return ipaddress.ip_address(ip)
    else:
        return ip


def _parse_subnet(subnet):
    """
    :type subnet: str | ipaddress.IPv4Network | ipaddress.IPv6Network
    :rtype: ipaddress.IPv4Network | ipaddress.IPv6Network
    """
    if isinstance(subnet, str):
        return ipaddress.ip_network(subnet)
    else:
        return subnet


def _clamp(x, mini, maxi):
    return max(min(x, maxi), mini)


class Quarisano(object):
    def __init__(self, subnets=None, thresh=None, block=None):
        """
        :type subnets: list[str]
        """
        if subnets is None:
            subnets = []
        if thresh is None:
            thresh = DEFAULT_THRESH
        if block is None:
            block = DEFAULT_BLOCK

        self.subnets = [_parse_subnet(subnet) for subnet in subnets]
        self.reliability = defaultdict(lambda: DEFAULT_RELIABILITY)
        self.packet_log = defaultdict(list)
        self.known_ip = set()
        self.thresh = thresh
        self.block = block

    def register_subnet(self, subnet):
        """
        :type subnet: str
        """
        self.subnets.append(_parse_subnet(subnet))

    def predict(self, packet):
        """
        :rtype: bool
        """
        self._update_log(packet)
        src_ip = _parse_ip(packet.src_ip)
        rel = self._update_reliability(src_ip)
        return rel > self.block

    def _update_reliability(self, src_ip):
        src_ip = _parse_ip(src_ip)
        dist = self._get_dist(src_ip)
        self.reliability[src_ip] += (dist - self.thresh + 1 * 10)
        self.reliability[src_ip] = _clamp(self.reliability[src_ip], 0.0, 1.0)
        return self.reliability[src_ip]

    def _get_dist(self, src_ip):
        src_ip = _parse_ip(src_ip)
        mat = self._build_matrix()
        mdist = EmpiricalCovariance().mahalanobis(mat)
        idx = sorted(list(self.known_ip)).index(src_ip) + 1
        return mdist[idx]

    def _build_matrix(self):
        return [
            self._build_vector(ip)
            for ip in self.known_ip
        ]

    def _build_vector(self, ip):
        return [
            v
            for k, v in sorted(Counter(self.packet_log[ip]))
        ]

    def _update_log(self, packet):
        src_ip = _parse_ip(packet.src_ip)
        self.packet_log[src_ip].append(self._get_subnet_id(packet.dst_ip))
        self.known_ip.add(src_ip)

    def _get_subnet_id(self, ip):
        """
        :type ip: str
        :rtype: int
        """
        ip = _parse_ip(ip)
        for idx, subnet in enumerate(self.subnets):
            if ip in subnet:
                return idx
        return -1