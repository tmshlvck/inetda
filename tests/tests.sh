#!/bin/bash

echo "Testing VRPS..."
echo "Expect result: 217.31.48.0/20,,[('217.31.48.0/20', 20, 'AS29134', 'ripe')]"
echo "Running test (1-2 minutes ETA)..."
../ipm.py --vrps routinator-vrps.csv 217.31.48.0/20,testlabel1
echo "Testing VRPS finished."

echo "Testing Linux IPv6 route table..."
echo "Expect result: fd00:a0b7::10:11:112:214,,fd00:a0b7::/64 dev tun0 proto 2 metric 50 pref medium"
echo "Running test (<0.1s ETA)..."
../ipm.py -r lrt6.txt fd00:a0b7::10:11:112:214
echo "Testing Linux IPv6 route table finished."

echo "Testing Linux IPv4 route table..."
echo "Expect result: 192.168.1.1,,192.168.1.1 dev bridge0 proto 4 scope 253 metric 50"
echo "Running test (<0.1s ETA)..."
../ipm.py -r lrt4.txt 192.168.1.1

echo "Expect result: 8.8.8.8,,default via 192.168.1.1 dev bridge0 proto 16 src 192.168.1.194 metric 425"
echo "Running test (<0.1s ETA)..."
../ipm.py -r lrt4.txt 8.8.8.8
echo "Testing Linux IPv4 route table finished."

echo "Testing CSV route table..."
echo "Expect result: 8.8.8.8,,['0.0.0.0/0', ' 192.168.1.1', ' bridge0 ']"
echo "Running test (<0.1s ETA)..."
../ipm.py -r rt.csv 8.8.8.8
echo "Testing CSV route table finished."
