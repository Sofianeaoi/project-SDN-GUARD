# -*- coding: utf-8 -*-
"""
SDN-GUARD - monitor.py

Ryu controller (OpenFlow 1.3) that behaves as a Learning Switch
and, at the same time, automatically builds a labeled traffic
dataset (flow_dataset.csv) used later to train the SDN-GUARD IDS.

Compatible with:
    - Ryu 4.x
    - OpenFlow 1.3
    - Mininet
    - Ubuntu 20.04 / Python 3

Run with:
    sudo ryu-manager monitor.py
"""

import os
import csv
from datetime import datetime

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3

from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import icmp
from ryu.lib.packet import in_proto
import sys
import os

sys.path.append(
    os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "traffic")
    )
)

# added a path to the scenario file 
from scenario import get_attack



class TrafficCollector(app_manager.RyuApp):
    """Learning switch + automatic traffic collector for SDN-GUARD."""

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # Exact column order requested for the SDN-GUARD dataset
    CSV_HEADERS = [
        "timestamp",
        "switch_id",
        "src_mac",
        "dst_mac",
        "src_ip",
        "dst_ip",
        "protocol",
        "application",
        "src_port",
        "dst_port",
        "packet_length",
        "icmp_type",
        "icmp_code",
        "tcp_flags",
        "label",
        "attack_type",
    ]

    # L4 ports used by the normal traffic generators
    HTTP_PORT = 8080
    SSH_PORT = 22

    def __init__(self, *args, **kwargs):
        super(TrafficCollector, self).__init__(*args, **kwargs)

        # dpid -> {mac: port}
        self.mac_to_port = {}

        self.csv_file = "flow_dataset.csv"

        self.label='Normal'
        self.attack_type="Attack"

        self._init_csv()

    # ------------------------------------------------------------------
    # CSV handling
    # ------------------------------------------------------------------
    def _init_csv(self):
        """Create the CSV file with headers only if it does not exist yet."""
        if not os.path.exists(self.csv_file):
            with open(self.csv_file, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(self.CSV_HEADERS)

    def _write_row(self, row):
        """Append a single row to the CSV file (robust to I/O errors)."""
        try:
            with open(self.csv_file, "a", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(row)
        except OSError as err:
            self.logger.error("Unable to write to %s: %s", self.csv_file, err)

    # ------------------------------------------------------------------
    # OpenFlow: initial handshake -> install table-miss flow
    # ------------------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                           ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions,
                 buffer_id=None, idle=0, hard=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                              actions)]
        if buffer_id is not None:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                     idle_timeout=idle, hard_timeout=hard,
                                     priority=priority, match=match,
                                     instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                     idle_timeout=idle, hard_timeout=hard,
                                     match=match, instructions=inst)
        datapath.send_msg(mod)

    def delete_flow(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if datapath.id not in self.mac_to_port:
            return

        for dst in self.mac_to_port[datapath.id].keys():
            match = parser.OFPMatch(eth_dst=dst)
            mod = parser.OFPFlowMod(
                datapath, command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                priority=1, match=match)
            datapath.send_msg(mod)

    # ------------------------------------------------------------------
    # Application-layer detection (port based, as requested)
    # ------------------------------------------------------------------
    def _detect_application(self, tcp_pkt, udp_pkt, icmp_pkt):
        """Detect HTTP / SSH / TCP / UDP / ICMP / Unknown from L4 ports."""
        if tcp_pkt:
            if tcp_pkt.src_port == self.HTTP_PORT or tcp_pkt.dst_port == self.HTTP_PORT:
                return "HTTP"
            if tcp_pkt.src_port == self.SSH_PORT or tcp_pkt.dst_port == self.SSH_PORT:
                return "SSH"
            return "TCP"

        if udp_pkt:
            return "UDP"

        if icmp_pkt:
            return "ICMP"

        return "Unknown"

    # ------------------------------------------------------------------
    # Feature extraction + CSV row creation
    # ------------------------------------------------------------------
    def _extract_and_save(self, msg, datapath, eth, pkt):
        """Build one dataset row from the current packet and store it."""
        timestamp = datetime.now().isoformat()

        src_mac = eth.src
        dst_mac = eth.dst

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)
        icmp_pkt = pkt.get_protocol(icmp.icmp)

        src_ip = ""
        dst_ip = ""
        protocol = ""
        src_port = ""
        dst_port = ""
        icmp_type = ""
        icmp_code = ""
        tcp_flags = ""

        if ip_pkt:
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst

        if tcp_pkt:
            protocol = "TCP"
            src_port = tcp_pkt.src_port
            dst_port = tcp_pkt.dst_port
            tcp_flags = tcp_pkt.bits
        elif udp_pkt:
            protocol = "UDP"
            src_port = udp_pkt.src_port
            dst_port = udp_pkt.dst_port
        elif icmp_pkt:
            protocol = "ICMP"
            icmp_type = icmp_pkt.type
            icmp_code = icmp_pkt.code
        elif ip_pkt:
            protocol = str(ip_pkt.proto)
        else:
            protocol = hex(eth.ethertype)

        application = self._detect_application(tcp_pkt, udp_pkt, icmp_pkt)
        

        # Placeholders filled later offline when building labeled datasets
        attack = get_attack()

        if attack == "NORMAL":
            label = "Normal"
            attack_type = "Normal"

        elif attack == "SYN":
            label = "Attack"
            attack_type = "SYN_FLOOD"

        elif attack == "ICMP":
            label = "Attack"
            attack_type = "ICMP_FLOOD"

        elif attack == "HTTP":
            label = "Attack"
            attack_type = "HTTP_GET_FLOOD"

        elif attack == "SSH":
            label = "Attack"
            attack_type = "SSH_FLOOD"

        else:
            label = "Normal"
            attack_type = "Normal"

        row = [
            timestamp,
            datapath.id,
            src_mac,
            dst_mac,
            src_ip,
            dst_ip,
            protocol,
            application,
            src_port,
            dst_port,
            len(msg.data),
            icmp_type,
            icmp_code,
            tcp_flags,
            label,
            attack_type,
        ]
        self._write_row(row)

    # ------------------------------------------------------------------
    # OpenFlow: PacketIn -> learning switch logic + collection
    # ------------------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        # --- Collect features and append a row to the CSV dataset ---
        self._extract_and_save(msg, datapath, eth, pkt)

        # --- Learning switch: decide the output port ---
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # --- Install a proactive flow entry for known destinations ---
        if out_port != ofproto.OFPP_FLOOD:
            if eth.ethertype == ether_types.ETH_TYPE_IP:
                ip_pkt = pkt.get_protocol(ipv4.ipv4)
                srcip = ip_pkt.src
                dstip = ip_pkt.dst
                proto = ip_pkt.proto

                if proto == in_proto.IPPROTO_ICMP:
                    t = pkt.get_protocol(icmp.icmp)
                    match = parser.OFPMatch(
                        eth_type=ether_types.ETH_TYPE_IP,
                        ipv4_src=srcip, ipv4_dst=dstip,
                        ip_proto=proto,
                        icmpv4_code=t.code, icmpv4_type=t.type)

                elif proto == in_proto.IPPROTO_TCP:
                    t = pkt.get_protocol(tcp.tcp)
                    match = parser.OFPMatch(
                        eth_type=ether_types.ETH_TYPE_IP,
                        ipv4_src=srcip, ipv4_dst=dstip,
                        ip_proto=proto,
                        tcp_src=t.src_port, tcp_dst=t.dst_port)

                elif proto == in_proto.IPPROTO_UDP:
                    u = pkt.get_protocol(udp.udp)
                    match = parser.OFPMatch(
                        eth_type=ether_types.ETH_TYPE_IP,
                        ipv4_src=srcip, ipv4_dst=dstip,
                        ip_proto=proto,
                        udp_src=u.src_port, udp_dst=u.dst_port)
                else:
                    match = parser.OFPMatch(
                        eth_type=ether_types.ETH_TYPE_IP,
                        ipv4_src=srcip, ipv4_dst=dstip,
                        ip_proto=proto)

                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 1, match, actions,
                                  msg.buffer_id, idle=60, hard=120)
                    return
                else:
                    self.add_flow(datapath, 1, match, actions,
                                  idle=60, hard=120)

            elif eth.ethertype == ether_types.ETH_TYPE_ARP:
                ar = pkt.get_protocol(arp.arp)
                match = parser.OFPMatch(
                    eth_type=ether_types.ETH_TYPE_ARP,
                    arp_op=ar.opcode, arp_spa=ar.src_ip,
                    arp_tpa=ar.dst_ip, arp_sha=ar.src_mac,
                    arp_tha=ar.dst_mac)
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 1, match, actions,
                                  msg.buffer_id, idle=60, hard=140)
                    return
                else:
                    self.add_flow(datapath, 1, match, actions,
                                  idle=60, hard=140)

        # --- Send the current packet out ---
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id,
            in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def set_attack(self, attack):

        if attack == "NORMAL":
            self.label = "Normal"   
            self.attack_type = "Normal"

        elif attack == "SYN":
            self.label = "Attack"
            self.attack_type = "SYN_FLOOD"

        elif attack == "ICMP":
            self.label = "Attack"
            self.attack_type = "ICMP_FLOOD"

        elif attack == "HTTP":
            self.label = "Attack"
            self.attack_type = "HTTP_GET_FLOOD"

        elif attack == "SSH":
            self.label = "Attack"
            self.attack_type = "SSH_FLOOD"