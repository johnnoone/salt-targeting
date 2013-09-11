'''

salt.utils.matching
~~~~~~~~~~~~~~~~~~~

Defines the most of matching.

'''

import collections
import fnmatch
import re
import socket
import struct

from salt._compat import string_types


def dig(data, expr, delim=':'):
    """Returns all relevant value -> pattern from data.
    """
    def decompose_expr(key):
        yield key, None
        value, a, b, c = '', '', '', ''
        while delim in key:
            key, b, c = key.rpartition(delim)
            value, a = c + a + value, b
            # print 'P:', key, '->', value
            yield key, value

    def explore(data, expr):
        if isinstance(data, list):
            # loop thru elements
            for element in data:
                for k, v in explore(element, expr):
                    yield k, v
        if isinstance(data, collections.Mapping):
            for key, value in decompose_expr(expr):
                if key in data:
                    for k, v in explore(data[key], value):
                        yield k, v
        else:
            yield data, expr

    if delim not in expr:
        raise Exception('expr {0} expect to have delim {1}'.format(
            repr(expr), repr(delim)
        ))

    for k, v in explore(data, expr):
        yield k, v


def glob_match(expr, value, delim=None):
    def match(expr, value):
        return fnmatch.fnmatch(value, expr)

    if delim is None:
        return match(expr, value)

    for value, expr in dig(value, expr, delim):
        if expr is None:
            return bool(value)
        if match(expr, str(value)):
            return True
    return False


def pcre_match(expr, value, delim=None):
    def match(expr, value):
        return pcre_compile(expr).match(value)

    if delim is None:
        return match(expr, value)

    for value, expr in dig(value, expr, delim):
        if expr is None:
            return bool(value)
        if match(expr, str(value)):
            return True
    return False


def ipcidr_match(expr, ipv4):
    matcher = CIDRMatcher(expr)
    if isinstance(ipv4, string_types):
        return matcher.match(ipv4)
    return any(matcher.match(ipaddr) for ipaddr in ipv4)


def glob_filter(expr, values):
    """
    Filters a list of values by glob.
    """
    return fnmatch.filter(values, expr)


def pcre_filter(expr, values):
    """
    Filters a list of values by pcre.
    """
    compiled = re.compile('^(' + expr + ')$')
    return set([value for value in value if compiled.match(value)])


def pcre_compile(expr):
    """
    Forces exact matching.
    """
    pattern = getattr(expr, 'patter', expr)
    return re.compile('^({0})$'.format(pattern))


class CIDRMatcher(object):
    def __init__(self, expr):
        self.expr = expr
        self.subnet = '/' in self.expr
        if self.subnet:
            netaddr, sep, bits = expr.partition('/')
            netmask = self.to_long(self.dotted_netmask(bits))
            network = self.to_long(netaddr) & netmask
            self.network = network
            self.netmask = netmask

    def match(self, ipaddr):
        if ipaddr == self.expr:
            return True

        if not self.subnet:
            return False

        return self.to_long(ipaddr) & self.netmask == self.network & self.netmask

    @staticmethod
    def to_long(ipaddr):
        return struct.unpack('=L', socket.inet_aton(ipaddr))[0]

    @staticmethod
    def dotted_netmask(mask):
        bits = 0xffffffff ^ (1 << 32 - int(mask)) - 1
        return socket.inet_ntoa(struct.pack('>I', bits))
