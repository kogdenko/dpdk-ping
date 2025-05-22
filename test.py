#!/usr/bin/python

import os
import psutil
import queue
import re
import select
import socket
import subprocess
import sys
import signal
import threading
import time
from inspect import currentframe
import unittest
from datetime import datetime

from scapy.all import *

VERBOSE = None
BUILDPATH = None
CORES = None

# mysql -D gbtcp -Bse "select * from test;"
DATABASE = None

def make_echo_packet(p):
    e = p
    e[Ether].src, e[Ether].dst = p[Ether].dst, p[Ether].src

    if e.haslayer(IP):
        e[IP].src, e[IP].dst = p[IP].dst, p[IP].src
    if e.haslayer(IPv6):
        e[IPv6].src, e[IPv6].dst = p[IPv6].dst, p[IPv6].src

    if e.haslayer(ICMP):
        e[ICMP].type = "echo-reply"
    elif e.haslayer(UDP):
        e[UDP].sport, e[UDP].dport = p[UDP].dport, p[UDP].sport
    elif e.haslayer(TCP):
        e[TCP].sport, e[TCP].dport = p[TCP].dport, p[TCP].sport
        e[TCP].flags = "SA"
    return e

def iter_to_str(it):
    if type(it) == list:
        return ','.join(iter_to_str(x) for x in it)
    elif type(it) == tuple:
        return "%d-%d" % (int(it[0]), int(it[1]))
    else:
        return str(it)

def bytes_to_str(b):
    return b.decode('utf-8').strip()

class dummy_database:
    def insert(*args, **kwargs):
        pass

class dpdk_ping_interface:
    def __init__(self, name, index):
        self.name = name
        self.index = index
        self.forward = None
        self.quiet = False
        self.core = CORES[0]
        self.smac = "22:4d:d9:98:03:%02x" % (index + 1)
        self.dmac = None
        self.tcp = False
        self.udp = False
        self.addresses6 = None
        self.srv6_src = None
        self.srv6_dst = None
        self.sip = "10.0.0.100"
        self.dip = "10.0.0.200"
        self.sport = 100
        self.dport = 200
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
        args = "-p %s -l %d" % (self.dpdk_name, self.core)

        if VERBOSE != None:
            args += " -V %d" % VERBOSE

        if self.quiet:
            args += " --quiet"

        if self.gateway != None:
            args += " -g %s" % self.gateway
        else:
            args += " -H %s" % self.smac

        if self.forward != None:
            args += " -f %s" % self.forward.dpdk_name
            return args

        if self.request:
            args += " -R 1"
            args += " -B %d" % self.bandwidth

            if self.tcp:
                args += " --tcp"

            if self.udp:
                args += " --udp"

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
        else:
            args += " -E 1"

        if self.addresses6 != None:
            args += " -6 %s" % iter_to_str(self.addresses6)

        if self.srv6_src != None:
            args += " --srv6-src %s" % self.srv6_src

        if self.srv6_dst != None:
            args += " --srv6-dst %s" % self.srv6_dst

        if self.sip != None:
            args += " -s %s" % iter_to_str(self.sip)
        if self.dip:
            args += " -d %s" % iter_to_str(self.dip)

        if self.sport != None:
            args += " -S %s" % iter_to_str(self.sport)

        if self.dport != None:
            args += " -D %s" % iter_to_str(self.dport)

        return args

    def wait_os_intf(self):
        return True

class dpdk_ping_memif_interface(dpdk_ping_interface):
    def __init__(self, name, index, role):
        super().__init__(name, index)
        smac = "22:4d:d9:99:%02x:01" % (index + 1)
        cmac = "22:4d:d9:99:%02x:02" % (index + 1)
        if role == "server":
            self.smac = smac
            self.dmac = cmac
        else:
            self.smac = cmac
            self.dmac = smac
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

class dpdk_ping_pg_interface(dpdk_ping_interface):
    def __init__(self, testcase, name, index):
        super().__init__(name, index)
        self.memif = testcase.create_memif_pair()
        self.smac = self.memif[0].smac
        self.dmac = self.memif[0].dmac
        self.dpdk_name = self.memif[0].dpdk_name

    def dpdk_args(self):
        return self.memif[0].dpdk_args()

class dpdk_ping_tap_interface(dpdk_ping_interface):
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

    def wait_os_intf(self):
        while self.inst.proc != None:
            addrs =  psutil.net_if_addrs()
            if self.name in addrs.keys():
                for sa in addrs[self.name]:
                    if sa.family == socket.AF_PACKET:
                        self.dmac = sa.address
                assert(self.dmac != None)
                self.init()
                return True
            time.sleep(0.1)
        return False

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

class dpdk_app():
    def __init__(self, index, exe):
        self.index = index
        self.proc = None
        self.exe = exe
        self.interfaces = []

    def add_interface(self, intf):
            intf.inst = self
            self.interfaces.append(intf)

    def get_interface(self, dpdk_name):
        for intf in self.interfaces:
            if intf.dpdk_name == dpdk_name:
                return intf
        return None

    def process_output(self, line):
        pass

    def reset(self):
        pass

    def monitor(self):
        while self.proc.poll() is None:
            out = self.proc.stdout.readline().decode("utf-8").strip("\n")
 
            if VERBOSE != None:
                print(out)

            self.process_output(out)

        out, err = self.proc.communicate()
        self.returncode = self.proc.returncode
        if self.returncode == -11:
            print("Process `%s` segfault\n" % self.comm)
        self.proc = None
        self.reset()

    def args(self):
        return ""

    def run(self):
        assert(self.proc == None)

        cores = []
        for intf in self.interfaces:
            if not intf.core in cores:
                cores.append(intf.core)

        cores = ",".join(str(x) for x in cores)

        self.comm = "%s --no-pci -l %s" % (self.exe, cores)

        self.comm += " --proc-type=primary --file-prefix=dpg%d" % self.index

        for intf in self.interfaces:
            self.comm += " "
            self.comm += intf.dpdk_args()

        self.comm += " -- " + self.args()

        if VERBOSE != None:
            print("")
            print(self.comm)

        self.proc = subprocess.Popen(self.comm.split(),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        self.thread = threading.Thread(target=self.monitor)
        self.thread.start()

        for intf in self.interfaces:
            if not intf.wait_os_intf():
                return False

        # FIXME: Wait memif interface
        time.sleep(1)

    def wait(self, timeout=None):
        self.thread.join(timeout)
        if timeout != None:
            if self.thread.is_alive():
              return None
        return self.returncode

    def sigint(self):
        if self.proc != None:
            self.proc.send_signal(signal.SIGINT)
            self.wait(10)

    def kill(self):
        if self.proc != None:
            self.proc.kill()
            self.wait(10)

class dpdk_ping(dpdk_app):
    def __init__(self, index):
        exe = BUILDPATH + "/dpdk-ping"

        super().__init__(index, exe)
        self.duration = None
        self.omit = None
        self.oselectors = []
        self.state_stat = False

    def reset(self):
        self.state_stat = False

    def process_output(self, line):
        if not self.state_stat:
            m = re.search(r'(.+): RPS: (\d+)->(\d+)', line) # \(step=(\d+), drops=(\d+)\)$', line)
            if m != None:
                intf = self.get_interface(m.group(1));
                if intf != None:
                    intf.rps.put(int(m.group(3)))
                return
            m = re.search(r'^ifname,', line)
            if m != None:
                self.state_stat = 1
                o = line.split(",")[1:]
                if len(self.oselectors):
                    assert(self.oselectors == o)
                self.oselectors = o
                return
        elif self.state_stat:
            if len(line) != 0 and len(self.oselectors) != 0:
                output = line.split(",")
                assert(len(output) - 1 == len(self.oselectors))
                intf = self.get_interface(output[0])
                if intf != None:
                    intf.output = dict(zip(self.oselectors, [int(i) for i in output[1:]]))

    def args(self):
        s = " --human-readable 0"
        if self.omit != None:
            s += " --omit %d" % self.omit

        if len(self.oselectors):
            s += " -o " + ','.join(self.oselectors)

        if self.duration != None:
            s += " -t %d" % self.duration

        excluded = set()
        for intf in self.interfaces:
            if intf.forward != None:
                excluded.add(intf.forward)

        first = True
        for intf in self.interfaces:
            if not intf in excluded:
                s += " "
                if not first:
                    s += "-- "
                first = False    
                s += intf.ping_args()

        return s

class dpdk_testpmd(dpdk_app):
    def __init__(self, index):
        super().__init__(index, "dpdk-testpmd")

    def args(self):
        s = "--txd=4096 --rxd=4096 --nb-cores=1 --forward-mode=io -a"
        return s

class dpdk_pcapreply(dpdk_app):
    def __init__(self, index):
        exe = BUILDPATH + "/dpdk-pcapreply"
        super().__init__(index, exe)

        self.rpath = None

    def args(self):
        s = "-t %d -w %s" % (self.timeout, self.wpath)
        if self.n_packets != None:
            s += " -n %d" % self.n_packets
        if self.rpath != None:
            s += " -r %s" % self.rpath
        return s

    def send_and_recv(self, packets, n_packets, timeout=1000):
        frame = inspect.stack()[1]
        path = "%s/%s_%d" % (self.testcase.testpath, frame.function, frame.lineno)

        if packets != None:
            self.rpath = path + "_out.pcap"
            wrpcap(self.rpath, packets)

        self.timeout = timeout
        self.n_packets = n_packets
        self.wpath = path + "_in.pcap"
        self.run()
        self.wait()

        return rdpcap(self.wpath)

class TestDpdkPing(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if DATABASE:
            self.database = Database()
        else:
            self.database = dummy_database

    def create_instance(self, classname):
        index = len(self.instances)
        inst = classname(index)
        inst.testcase = self
        self.instances.append(inst)
        return inst

    def create_dpdk_ping(self):
        return self.create_instance(dpdk_ping)

    def create_dpdk_testpmd(self):
        return self.create_instance(dpdk_testpmd)

    def create_dpdk_pcapreply(self):
        return self.create_instance(dpdk_pcapreply)

    def create_tap_interface(self):
        index = self.interface_index
        self.interface_index += 1
        return dpdk_ping_tap_interface("dpg%d" % index, index)

    def create_memif_pair(self):
        index = self.interface_index
        self.interface_index += 1
        return [
            dpdk_ping_memif_interface("net_memif%d" % index, index, "server"),
            dpdk_ping_memif_interface("net_memif%d" % index, index, "client")]

    def create_pg_interface(self):
        index = self.interface_index
        self.interface_index += 1
        name = "pg%d" % index
        return dpdk_ping_pg_interface(self, name, index)

    def setUp(self):
        self.testpath = BUILDPATH + "/test/" + self._testMethodName
        self.interface_index = 0
        os.mkdir(self.testpath)
        self.instances = []

    def tearDown(self):
        for inst in self.instances:
            inst.kill()
            inst.interfaces = []
        conf.ifaces.reload()

    def send_and_recv(self, iif, in_packets, n_out_packets, oif, timeout=1000):
        pcapreply = self.create_dpdk_pcapreply()
        self.assertTrue(type(iif) is dpdk_ping_pg_interface)
        self.assertTrue(type(oif) is dpdk_ping_pg_interface)
        pcapreply.add_interface(iif.memif[1])
        if oif != iif:
            pcapreply.add_interface(oif.memif[1])
        return pcapreply.send_and_recv(in_packets, n_out_packets)

    def assert_cores(self, n):
        if len(CORES) < n:
            self.skipTest("not enough cores: %d cores are required, but %d are available" %
                (n, len(CORES)))

    def save_to_database(self, data):
        test_name = inspect.stack()[1].function
        build_type = os.path.basename(BUILDPATH)
        self.database.insert(test_name, build_type, data);

    def validate_packet(self, packet):
        # Copy packet to remove checksums for futher checksum recalculation
        tmp = packet.__class__(bytes(packet))

        # Find checksum positions in packet
        counter = 0;
        checksums = []
        while True:
            layer = tmp.getlayer(counter)
            if layer == None:
                break

            layer = layer.copy()
            layer.remove_payload()

            for attr in ["chksum", "cksum"]:
                if hasattr(layer, attr):
                    checksums.append((counter, attr))
                    delattr(tmp[counter], attr)
            counter += 1

        # Recalculate checksums
        tmp = tmp.__class__(bytes(tmp))

        for counter, attr in checksums:
            layer = packet[counter]
            cksum = getattr(layer, attr)
            calc_cksum = getattr(tmp[counter], attr)
            self.assertEqual(cksum, calc_cksum, "%s %s 0x%hx (incorrect(->0x%hx))" %
                (layer.name, attr, cksum, calc_cksum))

    def test_000_pcap(self):
        self.assert_cores(2)

        testpmd = self.create_dpdk_testpmd()
        pcapreply = self.create_dpdk_pcapreply()
        memif0 = self.create_memif_pair()
        memif1 = self.create_memif_pair()

        memif0[0].core = CORES[0]
        memif1[0].core = CORES[1]
        testpmd.add_interface(memif0[0])
        testpmd.add_interface(memif1[0])
        testpmd.run()

        iif = memif0[1]
        oif = memif1[1]
        pcapreply.add_interface(iif)
        pcapreply.add_interface(oif)

        p = (
            Ether(src=iif.dmac, dst=iif.smac)
            / IP(src=iif.dip, dst=iif.sip, len=100)
            / ICMP(id=1, type="echo-request")
        )

        capture = pcapreply.send_and_recv(p, 1)
        self.assertEqual(len(capture), 1)
        c = capture[0]
        self.assertEqual(c[Ether].src, p[Ether].src)
        self.assertEqual(c[Ether].dst, p[Ether].dst)
        self.assertEqual(c[IP].src, p[IP].src)
        self.assertEqual(c[IP].dst, p[IP].dst)
        self.assertEqual(c[IP].len, p[IP].len)

    def test_port_duplicate(self):
        inst = self.create_dpdk_ping()
        if0 = self.create_tap_interface()
        inst.add_interface(if0)
        inst.add_interface(if0)

        inst.run()
        rc = inst.wait(0)
        self.assertEqual(rc, 1)

    def test_arp(self):
        inst = self.create_dpdk_ping()
        if0 = self.create_tap_interface()
        if0.gateway = "10.0.0.1"
        inst.add_interface(if0)
        inst.run()
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

        self.validate_packet(c);

        self.assertEqual(c[IP].src, if0.sip)
        self.assertEqual(c[IP].dst, if0.dip)

    def test_pdr(self):
        inst = self.create_dpdk_ping()
        if0 = self.create_tap_interface()
        inst.add_interface(if0)
        if0.bandwidth = 1000
        if0.pdr_start = 5
        if0.pdr_period = 2
        if0.pdr_percent = 50
        inst.run()

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

    def test_2interfaces(self):
        inst = self.create_dpdk_ping()

        for i in range(0, 2):
            intf = self.create_tap_interface()
            intf.sip = "1.1.1.10%d" % i
            intf.dip = "2.2.2.10%d" % i
            inst.add_interface(intf)

        inst.run()

        for intf in inst.interfaces:
            capture = intf.recv(1, "icmp")
            self.assertEqual(len(capture), 1)
            c = capture[0]
            self.assertEqual(c[IP].src, intf.sip)
            self.assertEqual(c[IP].dst, intf.dip)

    def test_001_icmp_request(self):
        inst = self.create_dpdk_ping()
        iif = self.create_pg_interface()
        iif.sip = "1.1.1.100"
        iif.dip = "2.2.2.100"     
        inst.add_interface(iif)
        inst.run()

        capture = self.send_and_recv(iif, None, 1, iif)
        self.assertEqual(len(capture), 1)
        c = capture[0]
        self.validate_packet(c)
        self.assertEqual(c[IP].src, iif.sip)
        self.assertEqual(c[IP].dst, iif.dip)
        self.assertEqual(c[ICMP].type, ICMP(type="echo-request").type)

        c = make_echo_packet(c)
        self.send_and_recv(iif, c, 0, iif)

        inst.sigint()
        self.assertGreater(iif.output["replies"], 0)

    def test_001_icmp_echo(self):
        inst = self.create_dpdk_ping()
        iif = self.create_pg_interface()
        iif.request = False
        iif.sip = "1.1.1.100"
        iif.dip = "2.2.2.100"     
        inst.add_interface(iif)
        inst.run()

        p = (
            Ether(src=iif.smac, dst=iif.smac)
            / IP(src=iif.dip, dst=iif.sip)
            / ICMP(id=333, seq=444, type="echo-request")
        )

        capture = self.send_and_recv(iif, p, 1, iif)
        self.assertEqual(len(capture), 1)
        c = capture[0]
        self.validate_packet(c)
        self.assertEqual(c[IP].src, iif.sip)
        self.assertEqual(c[IP].dst, iif.dip)
        self.assertEqual(c[ICMP].id, p[ICMP].id)
        self.assertEqual(c[ICMP].seq, p[ICMP].seq)
        self.assertEqual(c[ICMP].type, ICMP(type="echo-reply").type)

    def test_001_udp_request(self):
        inst = self.create_dpdk_ping()
        iif = self.create_pg_interface()
        iif.sip = "1.1.1.100"
        iif.sport = 100
        iif.dip = "2.2.2.100"
        iif.dport = 200
        iif.udp = True
        inst.add_interface(iif)
        inst.run()

        capture = self.send_and_recv(iif, None, 1, iif)
        self.assertEqual(len(capture), 1)
        c = capture[0]
        self.validate_packet(c)
        self.assertEqual(c[IP].src, iif.sip)
        self.assertEqual(c[IP].dst, iif.dip)
        self.assertEqual(c[UDP].sport, iif.sport)
        self.assertEqual(c[UDP].dport, iif.dport)

        c = make_echo_packet(c)
        self.send_and_recv(iif, c, 0, iif)

        inst.sigint()
        self.assertGreater(iif.output["replies"], 0)

    def test_001_udp_echo(self):
        inst = self.create_dpdk_ping()
        iif = self.create_pg_interface()
        iif.request = False
        iif.sip = "1.1.1.100"
        iif.dip = "2.2.2.100"
        sport = 100
        dport = 200
        inst.add_interface(iif)
        inst.run()

        p = (
            Ether(src=iif.smac, dst=iif.smac)
            / IP(src=iif.dip, dst=iif.sip)
            / UDP(sport=sport, dport=dport)
        )

        capture = self.send_and_recv(iif, p, 1, iif)
        self.assertEqual(len(capture), 1)
        c = capture[0]
        self.validate_packet(c)
        self.assertEqual(c[IP].src, iif.sip)
        self.assertEqual(c[IP].dst, iif.dip)
        self.assertEqual(c[UDP].sport, dport)
        self.assertEqual(c[UDP].dport, sport)

    def test_001_tcp_request(self):
        inst = self.create_dpdk_ping()
        iif = self.create_pg_interface()
        iif.sip = "1.1.1.100"
        iif.sport = 100
        iif.dip = "2.2.2.100"
        iif.dport = 200
        iif.tcp = True
        inst.add_interface(iif)
        inst.run()

        capture = self.send_and_recv(iif, None, 1, iif)
        self.assertEqual(len(capture), 1)
        c = capture[0]
        self.validate_packet(c)
        self.assertEqual(c[IP].src, iif.sip)
        self.assertEqual(c[IP].dst, iif.dip)
        self.assertEqual(c[TCP].sport, iif.sport)
        self.assertEqual(c[TCP].dport, iif.dport)
        self.assertEqual(c[TCP].flags, "S")

        c = make_echo_packet(c)
        self.send_and_recv(iif, c, 0, iif)

        inst.sigint()
        self.assertGreater(iif.output["replies"], 0)

    def test_001_tcp_echo(self):
        inst = self.create_dpdk_ping()
        iif = self.create_pg_interface()
        iif.request = False
        iif.sip = "1.1.1.100"
        iif.dip = "2.2.2.100"
        sport = 100
        dport = 200
        inst.add_interface(iif)
        inst.run()

        p = (
            Ether(src=iif.smac, dst=iif.smac)
            / IP(src=iif.dip, dst=iif.sip)
            / TCP(sport=dport, dport=sport, flags="S")
        )

        capture = self.send_and_recv(iif, p, 1, iif)
        self.assertEqual(len(capture), 1)
        c = capture[0]
        self.validate_packet(c)
        self.assertEqual(c[IP].src, iif.sip)
        self.assertEqual(c[IP].dst, iif.dip)
        self.assertEqual(c[TCP].sport, sport)
        self.assertEqual(c[TCP].dport, dport)
        self.assertEqual(c[TCP].flags, "SA")

    def test_002_ipv6_tunnel_request(self):
        inst = self.create_dpdk_ping()
        iif = self.create_pg_interface()
        iif.srv6_src = "2001::1"
        iif.srv6_dst = "2001::2"
        iif.sip = "1.1.1.100"
        iif.sport = 100
        iif.dip = "2.2.2.100"
        iif.dport = 200
        iif.tcp = True
        inst.add_interface(iif)
        inst.run()

        capture = self.send_and_recv(iif, None, 1, iif)
        self.assertEqual(len(capture), 1)
        c = capture[0]
        self.validate_packet(c)
        self.assertEqual(c[IPv6].src, iif.srv6_src)
        self.assertEqual(c[IPv6].dst, iif.srv6_dst)
        self.assertEqual(c[IPv6ExtHdrSegmentRouting].segleft, 0)
        self.assertEqual(len(c[IPv6ExtHdrSegmentRouting].addresses), 1)
        self.assertEqual(c[IPv6ExtHdrSegmentRouting].addresses[0], iif.srv6_dst)
        self.assertEqual(c[IPv6ExtHdrSegmentRouting].nh, 4)
        self.assertEqual(c[IP].src, iif.sip)
        self.assertEqual(c[IP].dst, iif.dip)
        self.assertEqual(c[TCP].sport, iif.sport)
        self.assertEqual(c[TCP].dport, iif.dport)
        self.assertEqual(c[TCP].flags, "S")

        c = make_echo_packet(c)
        self.send_and_recv(iif, c, 0, iif)

        inst.sigint()
        self.assertGreater(iif.output["replies"], 0)

    def test_002_ipv6_tunnel_echo(self):
        inst = self.create_dpdk_ping()
        iif = self.create_pg_interface()
        iif.request = False
        srv6_src = "2001::1"
        srv6_dst = "2001::2"
        iif.sip = "1.1.1.100"
        iif.dip = "2.2.2.100"
        sport = 100
        dport = 200
        inst.add_interface(iif)
        inst.run()

        p = (
            Ether(src=iif.smac, dst=iif.smac)
            / IPv6(src=srv6_src, dst=srv6_dst)
            / IP(src=iif.dip, dst=iif.sip)
            / TCP(sport=dport, dport=sport, flags="S")
        )

        capture = self.send_and_recv(iif, p, 1, iif)
        self.assertEqual(len(capture), 1)
        c = capture[0]
        self.validate_packet(c)
        self.assertEqual(c[IP].src, iif.sip)
        self.assertEqual(c[IP].dst, iif.dip)
        self.assertEqual(c[TCP].sport, sport)
        self.assertEqual(c[TCP].dport, dport)
        self.assertEqual(c[TCP].flags, "SA")

    def test_icmpv6_nd(self):
        inst = self.create_dpdk_ping()
        iif = self.create_pg_interface()
        iif.request = False
        src = "2001::1"
        dst = "2001::2"
        iif.addresses6 = dst

        inst.add_interface(iif)
        inst.run()

        p = (
            Ether(src=iif.smac, dst=iif.smac)
            / IPv6(src=src, dst=dst)
            / ICMPv6ND_NS(tgt=dst)
        )
       
        capture = self.send_and_recv(iif, p, 1, iif)
        self.assertEqual(len(capture), 1)
        c = capture[0]
        self.validate_packet(c)
        self.assertTrue(c.haslayer(ICMPv6ND_NA))
        self.assertTrue(c.haslayer(ICMPv6NDOptDstLLAddr))
        self.assertEqual(c[ICMPv6ND_NA].tgt, dst)
 
    def test_fwd(self):
        ip0 = "1.1.1.100"
        ip1 = "1.1.1.101"

        inst = self.create_dpdk_ping()
        if0 = self.create_pg_interface()
        if1 = self.create_pg_interface()
        if0.forward = if1

        inst.add_interface(if0)
        inst.add_interface(if1)

        inst.run()

        p = (
            Ether(src=if1.smac, dst=if1.smac)
            / IP(src=ip0, dst=ip1)
            / UDP(sport=100, dport=101)
        )

        #input("Press any key to continue");
        capture = self.send_and_recv(if0, p, 1, if1)
        self.assertEqual(len(capture), 1)
        c = capture[0]
        self.assertEqual(c[IP].src, ip0)
        self.assertEqual(c[IP].dst, ip1)

        p = make_echo_packet(c)
        capture = self.send_and_recv(if1, p, 1, if0)
        self.assertEqual(len(capture), 1)
        c = capture[0]
        self.assertEqual(c[IP].src, ip1)
        self.assertEqual(c[IP].dst, ip0)

    def echo_bandwidth(self, pong_if, ping_if, ping, pong, duration=12, bandwidth=100000000):
        pong_if.sip = None
        pong_if.dip = None
        pong_if.request = False
        pong_if.quiet = True
        pong.run()

        ping_if.sip = None
        ping_if.dip = None
        ping.duration = duration
        ping_if.bandwidth = bandwidth
        ping.omit = 2
        ping.oselectors = ["ipps", "opps", "requests", "replies"]
        ping.run()

        ping.wait()
        pong.kill()

    # dpdk-ping --> dpdk-ping
    def test_003_memif(self):
        self.assert_cores(2)
       
        ping = self.create_dpdk_ping()
        pong = self.create_dpdk_ping()
        memif = self.create_memif_pair()
        if0 = memif[0]
        if1 = memif[1]
        if0.core = CORES[0]
        if1.core = CORES[1]
        ping.add_interface(if1)
        pong.add_interface(if0)

        self.echo_bandwidth(if0, if1, ping, pong, 5, 1)
        requests = if1.output["requests"]
        replies = if1.output["replies"]
        self.assertGreaterEqual(requests, 4)
        self.assertGreaterEqual(replies, 4)

        # Benchmark
        self.echo_bandwidth(if0, if1, ping, pong)

        requests = if1.output["requests"]
        replies = if1.output["replies"]
        self.assertTrue(requests > 100000)
        self.assertTrue(requests - replies < 100000)

        self.save_to_database(if1.output)

    # dpdk-ping --> dpdk-testpmd --> dpdk-ping
    def test_003_memif(self):
        self.assert_cores(4)

        ping = self.create_dpdk_ping()
        pong = self.create_dpdk_ping()
        testpmd = self.create_dpdk_testpmd()
        memif0 = self.create_memif_pair()
        memif1 = self.create_memif_pair()
        if0 = memif0[1]
        if1 = memif1[1]
        if0.core = CORES[2]
        if1.core = CORES[3]
        memif0[0].core = CORES[0]
        memif1[0].core = CORES[1]

        testpmd.add_interface(memif0[0])
        testpmd.add_interface(memif1[0])
        testpmd.run()

        ping.add_interface(if1)
        pong.add_interface(if0)
        self.echo_bandwidth(if0, if1, ping, pong)

    def test_000_database(self):
        output = {}
        output["ipps"] = 100
        output["opps"] = 200
        self.save_to_database(output)

if __name__ == '__main__':
    conf.verb = 0

    VERBOSE = os.environ.get('VERBOSE')
    if VERBOSE != None:
        VERBOSE = int(VERBOSE)

    builddir = os.environ.get("BUILDDIR")
    if builddir == None:
        builddir = "./debug"
    BUILDPATH = os.path.abspath(builddir)

    CORES = os.environ.get("CORES")
    if CORES == None:
        CORES = [0]
    else:
        CORES = [int(i) for i in CORES.split(",")]

    DATABASE = os.environ.get("DATABASE")
    if DATABASE == None:
        DATABASE = False
    else:
        DATABASE = int(DATABASE) > 0
    if DATABASE:
        from database import Database

    testpath = BUILDPATH + "/test"
    try:
       shutil.rmtree(BUILDPATH + "/test")
    except FileNotFoundError:
        pass
    os.mkdir(testpath)

    failfast = os.environ.get("FAILFAST")
    if failfast != None:
        failfast = int(failfast) > 0

    try:
        unittest.main(failfast=failfast)
    except KeyboardInterrupt:
        pass

    sys.exit(0)
