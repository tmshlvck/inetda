#!/usr/bin/env python3
# coding: utf-8

"""
ipgrep

Copyright (C) 2020 Tomas Hlavacek (tmshlvck@gmail.com)

This module is an independent experiment.

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

import sys
import ipaddress
import argparse
import csv
import ipfind


def matchbool(m):
    if m == (None,None):
        return False
    return True


def main():
    def normalize_pfx(pfx):
        return ipaddress.ip_network(str(pfx).strip())
    
    def process_csv(lines, column, grep):
        for l in lines:
            try:
                lio = io.StringIO(l)
                rdr = csv.reader(lio)
                row = next(rdr)
                if matchbool(grep.matchBest(normalize_pfx(row[column]))):
                    print(l.strip())
            except:
                pass

    def process_re(lines, regexp, grep):
            try:
                mre = re.compile(regexp)
            except:
                print("Warn: Can not parse regexp!")
                return
            for l in lines():
                m = mre.match(l)
                if m:
                    if matchbool(grep.matchBest(normalize_pfx(m.group(1)))):
                        print(l.strip())

    def process_text(lines, grep):
        for l in lines:
            try:
                if matchbool(grep.matchBest(normalize_pfx(l.strip()))):
                    print(l.strip())
            except:
                raise
                pass


    parser = argparse.ArgumentParser(description='Search for IPs or subprefixes in IPv4/IPv6 prefixes')
    parser.add_argument('-n', '--network', metavar='NET', help='search for prefix')
    parser.add_argument('-f', '--file', metavar='FILE', help='load search IP/prefix list from file')
    parser.add_argument('-c', '--csv', metavar='N', help='read IP/prefixes from N-th column in CSV file(s)')
    parser.add_argument('-r', '--regexp', metavar='RE', help='read IP/prefixes from first group in RE matched in file(s)')
    parser.add_argument("files", help="files to match IP/prefixes in", metavar="FILES", nargs='*')

    args = parser.parse_args()

    if args.network:
        grep = ipfind.IPFind(table=ipaddress.ip_network(args.network))

    if args.file:
        grep = ipfind.IPFind()
        grep.readFile(args.file)

    if args.files:
        for f in args.files:
            with open(f, 'r') as fh:
                if args.csv:
                    process_csv(fh.readlines(), int(args.csv), grep)
                elif args.regexp:
                    process_re(fh.readlines(), args.regexp, grep)
                else:
                    process_text(fh.readlines(), grep)
    else:
        if args.csv:
            process_csv(sys.stdin.readlines(), int(args.csv), grep)
        elif args.regexp:
            process_re(sys.stdin.readlines(), args.regexp, grep)
        else:
            process_text(sys.stdin.readlines(), grep)



if __name__ == '__main__':
    main()
