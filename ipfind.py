#!/usr/bin/env python3
# coding: utf-8

"""
IPTree

Copyright (C) 2020 Tomas Hlavacek (tmshlvck@gmail.com)

This module is a part of inetda library.

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU Lesser General Public License as published by the Free
Software Foundation, either version 3 of the License, or (at your option) any
later version.
This program is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
You should have received a copy of the GNU General Public License along with
this program. If not, see <http://www.gnu.org/licenses/>.
"""

import sys
import ipaddress
from ipaddress import IPv4Network, IPv6Network, IPv4Address, IPv6Address
import pytricia


class IPFind(object):
    def __init__(self, table=None):
        """ table can be dict {ipaddress:data} or list of ipaddresses, data
        are interpreted as True in this case or one element of the list (ipaddress)
        """
        self._initTable()

        if table:
            if isinstance(table, dict):
                for k in table:
                    self.addToTable(ipaddress.ip_network(k), table[k])
            elif isinstance(table, list):
                for e in table:
                    self.addToTable(ipaddress.ip_network(e), True)
            else: # just one row
                self.addToTable(ipaddress.ip_network(table), True)


    def _initTable(self):
        self.table = {}


    def _fillTable(self, table):
        """ table can be dict {ipaddress:data} or list of ipaddresses, data
        are interpreted as True in this case or one element of the list (ipaddress)
        """
 
        if isinstance(table, dict):
            for k in table:
                self.addToTable(k, table[k])
        elif isinstance(table, list):
            for e in table:
                self.addToTable(e, True)
        else: # just one row
            self.addToTable(table, True)


    def addToTable(self, k, v):
        self.table.update({ipaddress.ip_network(k):v})


    def match(self, k):
        ipk = ipaddress.ip_network(k)
        for p in self.table:
            if ipk.subnet_of(p):
                yield (p, self.table[p])

    def matchBest(self, k):
        bk = None
        bv = None
        for k,v in self.match(k):
            if not bk or bk.prefixlen < k.prefixlen:
                bk = k
                bv = v
        return (bk, bv)


    def readPatternFile(self, filename):
        with open(filename, 'r') as fh:
            for l in fh.readlines():
                try:
                    self.addToTable(ipaddress.ip_network(l), True)
                except:
                    print("Warn: Can not make pattern from line %s" % str(l), file=sys.stdout)


    def readCSV(self, filename, keycol=0):
        """ Read CSV file, use keycol-th column as key (it must be IPv4 or IPv6 address)
        """
        with open(filename, 'r') as fh:
            rdr = csv.reader(fh)
            for r in rdr:
                try:
                    self.addToTable(ipaddress.ip_network(r[keycol]), r)
                except:
                    print("Warn: Can not make pattern from line %s" % str(r), file=sys.stdout)



class IPTreeFind(IPFind):
    def __init(self, table=None):
        super().__init__(table)


    def _initTable(self):
        self.t4 = pytricia.PyTricia(32)
        self.t6 = pytricia.PyTricia(128)


    def addToTable(self, k, v):
        ipk = ipaddress.ip_network(k)
        if isinstance(ipk, IPv6Network):
            self.t6.insert(ipk, v)
        elif isinstance(ipk, IPv4Network):
            self.t4.insert(ipk, v)
        else:
            raise ValueError("Can not add %s to IPTreeFind" % str(ipk))


    def _getTreeForAFI(self, ipk):
        if isinstance(ipk, IPv4Address) or isinstance(ipk, IPv4Network):
            return self.t4
        elif isinstance(ipk, IPv6Address) or isinstance(ipk, IPv6Network):
            return self.t6
        else:
            return None


    def match(self, k):
        ipk = ipaddress.ip_network(k)
        t = self._getTreeForAFI(ipk)
        p = t.get_key(ipk)
        while True:
            if p:
                yield (p, t[p])
            else:
                break
            p = t.parent(p)


    def matchBest(self, k):
        ipk = ipaddress.ip_network(k)
        t = self._getTreeForAFI(ipk)
        tk = t.get_key(ipk)
        if tk:
            return (tk, t[tk])
        else:
            return (None, None)



def main():
    pass
    # TODO: tests
#    f = IPTreeFind()
    f = IPFind()
    f.addToTable('192.168.1.0/24', 'xxx')
    f.addToTable('192.168.0.0/20', 'yyy')
    f.addToTable('192.168.0.0/16', 'zzz')
    f.addToTable('192.168.255.0/24', 'aaa')
    for k in ['192.168.1.1', '192.168.1.2','192.168.2.1','192.168.100.1']:
        print(str(list(f.match(k))))
        print(str(f.matchBest(k)))


if __name__ == '__main__':
    main()

