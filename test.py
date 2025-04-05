#!/usr/bin/python

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
        self.quiet = False
        self.lcore = 0
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

    def ping_args(self):
        args = "-p %s -l %d" % (self.dpdk_name, self.lcore)

        if self.request:
            args += " -R 1"
        else:
            args += " -E 1"

        args += " -B %d" % self.bandwidth
        if self.sip != None:
            args += " -s %s" % self.sip
        if self.dip:
            args += " -d %s" % self.dip

        if VERBOSE != None:
            args += " -V %d" % VERBOSE

        if self.quiet:
            args += " --quiet"

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

    def wait(self):
        pass

class DpdkPingMemifInterface(DpdkPingInterface):
    def __init__(self, name, index, role):
        super().__init__(name, index)
        self.role = role
        self.dpdk_name = name

    def dpdk_args(self):
        path = "/run/%s.sock" % self.name
        if self.role == "server":
            try:
                os.unlink(path)
            except:
                pass
        return ("--vdev=%s,role=%s,socket=%s,socket-abstract=no" %
            (self.name, self.role, path))

class DpdkPingTapInterface(DpdkPingInterface):
    def __init__(self, name, index):
        super().__init__(name, index)
        self.dpdk_name = "net_tap%d" % index

    def dpdk_args(self):
        return ("--vdev=net_tap%d,iface=%s,mac=%s" %
                (self.index, self.name, self.smac))

    def recv(self, count=1, filter="", timeout=1):
        return sniff(iface=self.name, count=count, filter=filter,
            timeout=timeout)

    def send(self, pkt):
         self.socket.send(pkt)#, iface=self.name)

    def wait(self):
        while True:
            assert(not self.inst.done)
            addrs =  psutil.net_if_addrs()
            if self.name in addrs.keys():
                for sa in addrs[self.name]:
                    if sa.family == socket.AF_PACKET:
                        self.dmac = sa.address
                assert(self.dmac != None)
                self.init()
                break
            time.sleep(0.1)

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

class DpdkPingInstance():
    def __init__(self, index):
        self.index = index
        self.duration = None
        self.done = False
        self.omit = None
        self.o = []
        self.interfaces = []

    def add_interface(self, intf):
            intf.inst = self
            self.interfaces.append(intf)

    def get_interface(self, dpdk_name):
        for intf in self.interfaces:
            if intf.dpdk_name == dpdk_name:
                return intf
        return None

    def monitor(self):
        stat = False

        while self.proc.poll() is None:
            line = self.proc.stdout.readline().decode("utf-8").strip("\n")
            
            if not stat:
                m = re.search(r'(.+): RPS: (\d+)->(\d+)', line) # \(step=(\d+), drops=(\d+)\)$', line)
                if m != None:
                    intf = self.get_interface(m.group(1));
                    if intf != None:
                        intf.rps.put(int(m.group(3)))
                    continue
                m = re.search(r'^ifname,', line)
                if m != None:
                    stat = 1
                    o = line.split(",")[1:]
                    if len(self.o):
                        assert(self.o == o)
                    self.o = o
                    continue
            elif stat:
                if len(line) != 0 and len(self.o) != 0:
                    output = line.split(",")
                    assert(len(output) - 1 == len(self.o))
                    intf = self.get_interface(output[0])
                    if intf != None:
                        intf.output = dict(zip(self.o, output[1:]))
                    
            if VERBOSE != None:
                print(line)
        self.done = True

    def start(self):
        self.comm = "./dpdk-ping --no-pci --proc-type=primary --file-prefix=dpg%d" % self.index
        for intf in self.interfaces:
            self.comm += " "
            self.comm += intf.dpdk_args()

        self.comm += " -- --human-readable 0"
        if self.omit != None:
            self.comm += " --omit %d" % self.omit

        if len(self.o):
            self.comm += " -o " + ','.join(self.o)

        if self.duration != None:
            self.comm += " -t %d" % self.duration

        for intf in self.interfaces:
            self.comm += " "
            self.comm += intf.ping_args()

        if VERBOSE != None:
            print("")
            print(self.comm)

        self.proc = subprocess.Popen(self.comm.split(),
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        self.thread = threading.Thread(target=self.monitor)
        self.thread.start()

        for intf in self.interfaces:
            intf.wait()

    def wait(self, timeout=None):
        self.thread.join()
        self.proc.communicate(timeout=timeout)
        self.proc = None

    def stop(self):
        if self.proc != None:
            self.proc.kill()
            self.wait(10)

class TestDpdkPing(unittest.TestCase):
    def create_tap(self, index):
        return DpdkPingTapInterface("dpg%d" % index, index)

    def create_memif(self, index, role):
        return DpdkPingMemifInterface("net_memif%d" % index, index, role)

    def create_instance(self):
        index = len(self.instances)
        inst = DpdkPingInstance(index)
        self.instances.append(inst)
        return inst

    def setUp(self):
        self.instances = []

    def tearDown(self):
        for inst in self.instances:
            inst.stop()
            inst.interfaces = []
        conf.ifaces.reload()

    def test_arp(self):
        inst = self.create_instance()
        if0 = self.create_tap(0)
        if0.gateway = "10.0.0.1"
        inst.add_interface(if0)
        inst.start()
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
        inst = self.create_instance()
        if0 = self.create_tap(0)
        inst.add_interface(if0)
        if0.bandwidth = 1000
        if0.pdr_start = 5
        if0.pdr_period = 2
        if0.pdr_percent = 50
        inst.start()

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

    def test_memif(self):
        inst0 = self.create_instance()
        if0 = self.create_memif(0, "server")
        if0.lcore = 1
        if0.sip = None
        if0.dip = None
        if0.request = False
        if0.quiet = True
        inst0.add_interface(if0)
        inst0.start()

        time.sleep(1)

        inst1 = self.create_instance()
        if1 = self.create_memif(0, "client")
        if1.lcore = 2
        if1.sip = None
        if1.dip = None
        if1.bandwidth = 10000000
        inst1.duration = 12
        inst1.omit = 2
        inst1.o = ["ipps", "opps", "requests", "replies"]
        inst1.add_interface(if1)
        inst1.start()

        inst1.wait()
        self.assertAlmostEqual(if1.output["requests"], if1.output["replies"], 6)
        

if __name__ == '__main__':
    conf.verb = 0

    VERBOSE = os.environ.get('VERBOSE')
    if VERBOSE != None:
        VERBOSE = int(VERBOSE)

    try:
        unittest.main()
    except KeyboardInterrupt:
        pass

    sys.exit(0)
