#!/usr/bin/env python3
# coding: utf-8

"""
ipm - IP match

Copyright (C) 2014-2022 Tomas Hlavacek (tmshlvck@gmail.com)

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

from typing import *
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
    # Warning: The value of internal nodes are set to None. This dumps the raw tree,
    # but post-processing is needed to obtain only data-carrying tree nodes.
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

    raise KeyError(f"{key} not found")


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
      raise KeyError(f"{key} not found")


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
    except KeyError:
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


class VRPS:
  def __init__(self):
    self.trees = { 4: IPTree(4), 6: IPTree(6) }

  @staticmethod
  def _read_vrps(vrpsfile: IO) -> Generator[None, Tuple[Union[ipaddress.IPv4Network,ipaddress.IPv6Network], int, str, str], None]:
    """
    read VRPS CSV file from routinator
    vrfpsfile: file object
    output: generator returning tupes (prefix, maxlen, asn, rir)

    example input line: AS1299,103.29.146.0/24,24,apnic
    example output: (IPv4Network(103.29.146.0/24), 24, 'AS1299', 'apnic')
    """
    rdr = csv.reader(vrpsfile)
    for r in rdr:
      try:
        addr = ipaddress.ip_network(r[1].strip())
        yield (addr, int(r[2].strip()), r[0].strip(), r[3].strip()) # generate tuples (ipaddress, maxlen, asn, rir)
      except:
        pass

  def readVRPS(self, vrpsfile: IO):
    """
    read open VRPS CSV file from routinator
    use with external open:
    vrps = VRPS()
    with open('vrps.csv', 'r') as fh
      vrps.read_vrps(fh)
    """
    for pfx,ml,asn,rir in self._read_vrps(vrpsfile):
      if not pfx in self.trees[pfx.version]:
        self.trees[pfx.version][pfx] = set()
      self.trees[pfx.version][pfx].add((pfx,ml,asn,rir))


  def readVRPSFromFile(self, vrpsfilename: str):
    with open(vrpsfilename, 'r') as fh:
      return self.readVRPS(fh)


  def matchPfx(self, inpfx: Union[ipaddress.IPv4Network,ipaddress.IPv6Network]) -> Generator[None, Tuple[Union[ipaddress.IPv4Network,ipaddress.IPv6Network], int, str, str], None]:
    """
    Find all relevant VRPS for a prefix
    returns Generator of tuples (pfx:Union[ipaddress.IPv4Network,ipaddress.IPv6Network], ml: int, asn: str, rir: str)
    """
    for node in self.trees[inpfx.version].traverse(inpfx):
      if node.value:
        for nv in node.value:
          pfx,ml,asn,rir = nv
          if inpfx.prefixlen <= ml or inpfx.num_addresses == 1:
              yield (pfx,ml,asn,rir)
      


class RTSim:
  def __init__(self):
    self.trees = { 4: IPTree(4), 6: IPTree(6) }

  @staticmethod
  def _read_csv(csvfile):
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

  @staticmethod
  def _read_linux_rt(lrtfile):
    """
    read file with ip -N route >$file or ip -N -6 route >$file
    """
    def guess_afi(l):
      for g in l.split(' '):
        try:
          dip = ipaddress.ip_network(g)
          return dip.version
        except:
          pass
      return None


    for l in lrtfile:
      l = l.strip()
      try:
        grps = l.split(' ', 1)
        if grps[0] == 'default':
          afi = guess_afi(l)
          if afi == 4:
            yield (ipaddress.IPv4Network('0.0.0.0/0'), l)
          elif afi == 6:
            yield (ipaddress.IPv6Network('::/0'), l)
          else:
            raise RuntimeError(f'Can not detect AFI for default route: {l}')
        else:
          yield (ipaddress.ip_network(grps[0]), l) # generate tuples (IPv{4,6}Network, RT row)
      except:
        raise

  def readRT(self, infile: IO, form="csv"):
    """
    rtfile: open file handle to read input from
    form: "linuxrt"|"csv" - the format of the input
    """
    if form == 'linuxrt':
    # we match IP addresses in a routing table, using the longest prefix match 
      rtgen = self._read_linux_rt(infile)

    elif form == 'csv':
    # the same, but we have the "routing table" in a CSV file
      rtgen = self._read_csv(infile)

    for a,r in rtgen:
      if not a in self.trees[a.version]:
        self.trees[a.version][a] = []
      self.trees[a.version][a].append(r)


  def matchIP(self, ipa):
    return self.trees[ipa.version].lookupLongestPrefix(ipa)



@click.command(help='find IP subnets that contain IP addresses from args or STDIN\nThe args or STDIN has to contain IP address in the beginning, then more data can be present (delimited by space or comma)')
@click.option('-c', '--csv', 'csvfile', help="parse CSV file, find IP/prefixes there", type=click.File('r'))
@click.option('-r', '--routetable', 'routetable', help="parse Linux/Cisco route table", type=click.File('r'))
@click.option('-v', '--vrps', 'vrpsfile', help="parse VRPs CSV file from routinator", type=click.File('r'))
@click.option('-n', '--include-no-match', 'nomatchincl', help="include lines with no matche (with empty resut)", is_flag=True)
@click.argument('ips', nargs=-1)
def main(csvfile, routetable, vrpsfile, ips, nomatchincl):
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

  if not ips:
    ips = sys.stdin

  if routetable or csvfile:
    rtsim = RTSim()

    # we match IP addresses in a routing table, using the longest prefix match 
    if routetable:
      rtsim.readRT(routetable, 'linuxrt')

    # the same, but we have the "routing table" in a CSV file
    if csvfile:
      rtsim.readRT(csvfile, 'csv')

    for ipa,indata in normalize_input(ips):
      ipap = ipaddress.ip_address(ipa)
      try:
        res = rtsim.matchIP(ipap)
        if res:
          for r in res:
            output(ipa, indata, r)
        else:
          if nomatchincl:
            output(ipa, indata, None)
      except KeyError:
        if nomatchincl:
          output(ipa, indata, None)

  # this is specical case: we match IP networks in a VRPS table, which is an IP network filter
  # and it contains networks and maxlens
  elif vrpsfile:
    vrps = VRPS()
    vrps.readVRPS(vrpsfile)
    
    for ipn,indata in normalize_input(ips):
      ipnp = ipaddress.ip_network(ipn.strip())

      matches = set(vrps.matchPfx(ipnp))
      output(ipn, indata, [(str(m[0]),)+tuple(m[1:]) for m in matches])


if __name__ == '__main__':
#  tree_test()
  main()

