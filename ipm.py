#!/usr/bin/env python3
# coding: utf-8

"""
ipm - IP match

Copyright (C) 2014-2021 Tomas Hlavacek (tmshlvck@gmail.com)

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.
This program is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
You should have received a copy of the GNU General Public License along with
this program. If not, see <http://www.gnu.org/licenses/>.
"""

import ipaddress
import click
import csv
import sys

class IPTree:
  class IPTreeNode:
    __slots__ = 'zero', 'one', 'key', 'value'

    def __init__(self):
      self.zero = None
      self.one = None
      self.key = None
      self.value = None

  def __init__(self, ipv=4):
    """
      ipv = 4|6
    """
    if ipv != 4 and ipv != 6:
      raise ValueError("IP version must be 4 or 6")
    self.ipv = ipv
    self.root = self.IPTreeNode()

  def _bits(self, abytes, limit=None):
    if limit == None:
      limit = 32 if self.ipv == 4 else 128

    i = 0
    for byte in abytes:
      for _ in range(8):
        yield bool(0b10000000 & byte)
        byte = byte << 1
        i += 1
        if i >= limit:
          return


  def traverse(self, key, create_nodes=False):
    assert(key.version == self.ipv)
    if isinstance(key, ipaddress.IPv4Network) or isinstance(key, ipaddress.IPv6Network):
      abits = self._bits(key.network_address.packed, key.prefixlen)
    elif isinstance(key, ipaddress.IPv4Address) or isinstance(key, ipaddress.IPv6Address):
      abits = self._bits(key.packed)
    else:
      raise TypeError("ipaddress.IPv4/6Address or IPv4/6Network expected")

    point = self.root
    for b in abits:
      if b:
        if create_nodes and not point.one:
          point.one = self.IPTreeNode()
        point = point.one
      else:
        if create_nodes and not point.zero:
          point.zero = self.IPTreeNode()
        point = point.zero

      if point:
        yield point
      else:
        break


  def dump(self, point=None):
    if point == None:
      point = self.root

    yield point

    if point.zero:
      yield from self.dump(point.zero)

    if point.one:
      yield from self.dump(point.one)


  def findExact(self, key):
    for point in self.traverse(key):
      if point.key == key:
        return point

    raise IndexError(f"{key} not found")


  def lookupExact(self, key):
    return self.findExact(key).value


  def findLongestPrefix(self, key):
    bestpoint = None
    for point in self.traverse(key):
      if point.value != None:
        bestpoint = point
    return bestpoint


  def lookupLongestPrefix(self, key):
    best = self.findLongestPrefix(key)
    if best:
      return best.value
    else:
      raise IndexError(f"{key} not found")


  def findAll(self, key):
    for point in self.traverse(key):
      if point.value != None:
        yield point


  def lookupAll(self, key):
    for point in self.findAll(key):
      yield point.value


  def __getitem__(self, key):
    return self.lookupExact(key)


  def __setitem__(self, key, value):
    for point in self.traverse(key, create_nodes=True):
      pass
    point.key = key
    point.value = value


  def __contains__(self, key):
    try:
      self.lookupExact(key)
      return True
    except IndexError:
      return False


  def __repr__(self):
    r = ''
    for node in self.dump():
      if node.key:
        r += f'{node.key}:{node.value}\n'
    return r


  def __str__(self):
    return self.__repr__()


def tree_test():
  pfxs = { 4: IPTree(4), 6: IPTree(6) }
  n1 = ipaddress.IPv4Network('192.168.0.0/16')
  pfxs[n1.version][n1] = "test1"
  n2 = ipaddress.IPv4Network('192.168.1.0/24')
  pfxs[n2.version][n2] = "test2"

  print(str(pfxs[4]))

  print(pfxs[4][n1])
  print(pfxs[4][n2])

  print(list(pfxs[4].lookupAll(ipaddress.IPv4Address('192.168.0.5'))))
  print(list(pfxs[4].lookupAll(ipaddress.IPv4Address('192.168.1.5'))))





def read_vrps(vrpsfile):
  """
  read VRPS CSV file from routinator
  """
  rdr = csv.reader(vrpsfile)
  for r in rdr:
    try:
      addr = ipaddress.ip_network(r[1].strip())
      yield (addr, int(r[2].strip()), r[0].strip(), r[3].strip()) # generate tuples (ipaddress, maxlen, asn, rir)
    except:
      pass


def read_csv(csvfile):
  """
  read arbitrary CSV file and find IP network in each line
  """
  rdr = csv.reader(csvfile)
  for r in rdr:
    for e in r:
      try:
        addr = ipaddress.ip_network(e.strip())
        yield (addr, r) # generate tuples (ipaddress, CSV row)
        break # go to next row in CSV
      except:
        pass


def read_linux_rt(lrtfile):
  """
  read file with ip -n route >$file or ip -n -6 route >$file
  """
  for l in lrtfile:
    try:
      grps = l.strip().split(' ', 1)
      addr = ipaddress.ip_network(grps[0])
      yield (addr, grps[1]) # generate tuples (ipaddress, rest of the row)
    except:
      raise



def normalize_input(instr):
  DELIMITERS = [' ', ',']

  def normalize_line(l):
    ls = l.strip()
    for d in DELIMITERS:
      spl = ls.split(d, 1)
      if len(spl) == 2:
        return spl
    else:
      return (ls,None)

  for l in instr:
    yield normalize_line(l)


def output(ip, indata, outdata):
  print(f"{ip},{str(indata) if indata else ''},{str(outdata)}")


@click.command(help='find IP subnets that contain IP addresses from args or STDIN\nThe args or STDIN has to contain IP address in the beginning, then more data can be present (delimited by space or comma)')
@click.option('-c', '--csv', 'csvfile', help="parse CSV file, find IP/prefixes there", type=click.File('r'))
@click.option('-r', '--routetable', 'routetable', help="parse Linux/Cisco route table", type=click.File('r'))
@click.option('-v', '--vrps', 'vrpsfile', help="parse VRPs CSV file from routinator", type=click.File('r'))
@click.argument('ips', nargs=-1)
def main(csvfile, routetable, vrpsfile, ips):
  pfxs = { 4: IPTree(4), 6: IPTree(6) }

  if not ips:
    ips = sys.stdin

  if routetable or csvfile:
    # we match IP addresses in a routing table, using the longest prefix match 
    if routetable:
      rtgen = read_linux_rt(csvfile)

    # the same, but we have the "routing table" in a CSV file
    if csvfile:
      rtgen = read_csv(csvfile)

    for a,r in rtgen:
      if not a in pfxs[a.version]:
        pfxs[a.version][a] = []
      pfxs[a.version][a].append(r)

    for ipa,indata in normalize_input(ips):
      ipap = ipaddress.ip_address(ipa)
      res = pfxs[ipap.version].lookupLongestPrefix(ipap)
      if res:
        for r in res:
          output(ipa, indata, r)

  # this is specical case: we match IP networks in a VRPS table, which is an IP network filter
  # and it contains networks and maxlens
  elif vrpsfile:
    for pfx,ml,asn,rir in read_vrps(vrpsfile):
      if not pfx in pfxs[pfx.version]:
        pfxs[pfx.version][pfx] = set()
      pfxs[pfx.version][pfx].add((str(pfx),ml,asn,rir))

    for ipn,indata in normalize_input(ips):
      ipnp = ipaddress.ip_network(ipn.strip())

      matches = set()
      for node in pfxs[ipnp.version].traverse(ipnp):
        if node.value:
          for nv in node.value:
            pfx,ml,asn,rir = nv
            if ipnp.prefixlen <= ml or ipnp.num_addresses == 1:
              matches.add(nv)
      output(ipn, indata, matches)


if __name__ == '__main__':
#  tree_test()
  main()
