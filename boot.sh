#!/bin/sh

ethtool -K eth0 rx off tx off gro off tso off gso off
ethtool -K eth1 rx off tx off gro off tso off gso off

insmod /root/cryptor.ko
