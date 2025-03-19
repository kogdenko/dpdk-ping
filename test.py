#!/usr/bin/python

import argparse
import os
import psutil
import queue
import re
import select
import socket
import subprocess
import sys
import threading
import time
import unittest

from scapy.all import *

VERBOSE = None

def make_echo_packet( p):
    e = p
    e[Ether].src, e[Ether].dst = p[Ether].dst, p[Ether].src
    e[IP].src, e[IP].dst = p[IP].dst, p[IP].src
    if e.haslayer(ICMP):
        e[ICMP].type = "echo-reply"
    elif e.haslayer(UDP):
        e[UDP].sport, e[UDP].dport = p[UDP].dport, p[UDP].sport
    elif e.haslayer(TCP):
        pass
    return e

class DpdkPingInterface:
    def __init__(self, name, index):
        self.name = name
        self.index = index
        self.smac = "22:4d:d9:98:03:%02x" % (index + 1)
        self.dmac = None
        self.sip = "10.0.0.100"
        self.dip = "10.0.0.200"
        self.bandwidth = 1
        self.rps = queue.Queue()
        self.pdr = None
        self.pdr_period = None
        self.pdr_start = None
        self.pdr_percent = None
        self.pdr_step = None
        self.gateway = None
        self.request = True

    def init(self):
        self.socket = conf.L2socket(iface=self.name)

    def args(self):
        args = "-p net_tap%d -l 0" % self.index

        if self.request:
            args += " -R 1"
        else:
            args += " -E 1"

        args += " -B %d -s %s -d %s" % (self.bandwidth, self.sip, self.dip)

        if VERBOSE != None:
            args += " -V %d" % VERBOSE

        if self.gateway != None:
            args += " -g %s" % self.gateway
        else:
            args += " -H %s" % self.smac

        if self.pdr != None:
            args += " --pdr"
        if self.pdr_period != None:
            args += " --pdr-period %d" % self.pdr_period
        if self.pdr_start != None:
            args += " --pdr-start %d" % self.pdr_start
        if self.pdr_percent != None:
            args += " --pdr-percent %f" % self.pdr_percent
        if self.pdr_step != None:
            args += " --pdr-step %d" % self.pdr_step

        return args

    def recv(self, count=1, filter="", timeout=1):
        return sniff(iface=self.name, count=count, filter=filter,
            timeout=timeout)

    def send(self, pkt):
         self.socket.send(pkt)#, iface=self.name)

    def wait_pdr_report(self, echo=True):
        while not self.rps.empty():
            self.rps.get_nowait()

        while self.rps.empty():
            capture = self.recv(1, "ip && (icmp||udp||tcp)", 0.1)
            if echo:
                for c in capture:
                    e = make_echo_packet(c)
                    self.send(e)

        return self.rps.get()


class TestDpdkPing(unittest.TestCase):
    def create_dpg_intf(self):
        assert(self.intf == None)
        self.intf = DpdkPingInterface("dpg0", 0)
        return self.intf

    def monitor_dpg(self):
        while self.proc.poll() is None:
            line = self.proc.stdout.readline().decode("utf-8").strip()

            m = re.search(r'RPS: (\d+)->(\d+)', line)
            if m != None:
                self.intf.rps.put(int(m.group(2)))

            if VERBOSE != None:
                print(line)

        if not self.down:
            print(("Process unexpectedly closed with status %d" %
                self.proc.returncode))
            os._exit(1)

    def start_dpg(self):
        assert(self.intf != None)
        intf = self.intf 
        args = "./dpdk-ping -m 10000 --no-huge --no-pci "
        args += ("--vdev=net_tap%d,iface=%s,mac=%s" %
            (intf.index, intf.name, intf.smac))
        args += " -- --human-readable-number 0"

        args += " "
        args += self.intf.args()

        if VERBOSE != None:
            print("")
            print(args)

        self.proc = subprocess.Popen(args.split(),
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        self.thread = threading.Thread(target=self.monitor_dpg)
        self.thread.start()

        while True:
            addrs =  psutil.net_if_addrs()
            if self.intf.name in addrs.keys():
                for sa in addrs[self.intf.name]:
                    if sa.family == socket.AF_PACKET:
                        self.intf.dmac = sa.address
                assert(self.intf.dmac != None)
                self.intf.init()
                break
           
            time.sleep(0.1)

    def setUp(self):
        self.proc = None
        self.intf = None
        self.down = False

    def tearDown(self):
        self.down = True
        if self.proc != None:
            self.proc.kill()
            self.thread.join()
            self.proc.communicate(timeout=10)
            self.proc = None
        self.intf = None
        conf.ifaces.reload()

    def test_arp(self):
        if0 = self.create_dpg_intf()
        if0.gateway = "10.0.0.1"
        self.start_dpg()
        capture = if0.recv(1, "arp")
        self.assertEqual(len(capture), 1)
        c = capture[0]
        self.assertEqual(c[ARP].pdst, if0.gateway)
        ar = c
        ar[Ether].dst = c[Ether].src
        ar[Ether].src = if0.dmac
        ar[ARP].psrc, ar[ARP].pdst = ar[ARP].pdst, ar[ARP].psrc
        ar[ARP].hwdst = ar[ARP].hwsrc
        ar[ARP].hwsrc = if0.dmac
        ar[ARP].op = 2

        if0.send(ar)

        capture = if0.recv(1, "icmp")
        self.assertEqual(len(capture), 1)
        c = capture[0]

        self.assertEqual(c[IP].src, if0.sip)
        self.assertEqual(c[IP].dst, if0.dip)

    def test_pdr(self):
        if0 = self.create_dpg_intf()
        if0.bandwidth = 1000
        if0.pdr_start = 5
        if0.pdr_period = 2
        if0.pdr_percent = 50
        self.start_dpg()

        # Slow start
        rps = if0.wait_pdr_report()
        self.assertEqual(rps, 50)

        # Congestion avoidance
        rps = if0.wait_pdr_report(False)
        self.assertEqual(rps, 38)

        rps = if0.wait_pdr_report(False)
        self.assertEqual(rps, 29)

        rps = if0.wait_pdr_report(False)
        self.assertEqual(rps, 22)

        rps = if0.wait_pdr_report(False)
        self.assertEqual(rps, 17)

        # Stop loss
        rps = if0.wait_pdr_report()
        self.assertEqual(rps, 18)

        rps = if0.wait_pdr_report()
        self.assertEqual(rps, 19)


if __name__ == '__main__':
    conf.verb = 0

    parser = argparse.ArgumentParser()
    parser.add_argument('-v', dest='verbose', action='count')
    args, _ = parser.parse_known_args()
    if args.verbose != None and args.verbose > 1:
        VERBOSE = args.verbose - 2

    unittest.main()
