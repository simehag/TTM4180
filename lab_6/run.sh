#!/bin/bash

# cleanup
sudo mn -c
sudo fuser -k 6633/tcp
sudo killall controller

# Launch processes
LAUNCH_CONTROLLER='./pox.py log.level --DEBUG SimpleLoadBalancer --loadbalancer=10.0.0.254 --servers=10.0.0.5,10.0.0.6,10.0.0.7'
LAUNCH_MININET='sudo mn --topo single,7 --mac --controller remote --switch ovsk'
SET_OPENFLOW_VERSION='sudo  ovs−vsctl  set  bridge  s1  protocols=OpenFlow10 &'

xfce4-terminal --hold --geometry 100x30+0+0 --command "$LAUNCH_MININET" -T 'Mininet' &
xfce4-terminal --hold --geometry 120x30+880+0 --working-directory='/home/ubuntu/pox' --command "$LAUNCH_CONTROLLER"  -T 'Controller' &
