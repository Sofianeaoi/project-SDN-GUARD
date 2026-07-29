from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import icmp
from ryu.ofproto import ofproto_v1_3

from ryu.lib.packet import arp
from ryu.lib.packet import ether_types
from ryu.lib.packet import in_proto
import csv
import os
from datetime import datetime

class TrafficCollector(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    

    CSV_HEADERS = [
        "timestamp",
        "switch",
        "src_mac",
        "dst_mac",
        "src_ip",
        "dst_ip",
        "protocol",
        "src_port",
        "dst_port",
        "packet_length",
        "icmp_type",
        "icmp_code",
        "tcp_flags",
        "application",
    ]

    def __init__(self, *args, **kwargs):
        super(TrafficCollector, self).__init__(*args, **kwargs)

        self.mac_to_port = {}

        self.csv_file = "flow_dataset.csv"

        
        def _init_csv(self):
              if not os.path.exists(self.csv_file):
                    with open(self.csv_file, "w", newline="") as f:
                        writer = csv.writer(f)
                        writer.writerow(self.CSV_HEADERS)

        self._init_csv()

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                           ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None,
                 idle=0, hard=0):
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

        for dst in self.mac_to_port[datapath.id].keys():
            match = parser.OFPMatch(eth_dst=dst)
            mod = parser.OFPFlowMod(
                datapath, command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                priority=1, match=match)
            datapath.send_msg(mod)

    def _detect_application(self, tcp_pkt, udp_pkt):
        """Detects the application layer protocol from L4 ports."""
        application = ""

        if tcp_pkt:
            if tcp_pkt.dst_port == 8080 or tcp_pkt.src_port == 80:
                application = "HTTP"
            elif tcp_pkt.dst_port == 22 or tcp_pkt.src_port == 22:
                application = "SSH"
        

        elif udp_pkt:
            if udp_pkt.dst_port==9900:
                application="UDP"


        return application

    def _extract_and_save(self, msg, datapath, eth, pkt):
        """Extracts packet features and writes a row to the CSV file."""
        timestamp = datetime.now()

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

        else:
            protocol = hex(eth.ethertype)

        application = self._detect_application(tcp_pkt, udp_pkt)

        with open(self.csv_file, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                timestamp,
                datapath.id,
                src_mac,
                dst_mac,
                src_ip,
                dst_ip,
                protocol,
                src_port,
                dst_port,
                len(msg.data),
                icmp_type,
                icmp_code,
                tcp_flags,
                application,
            ])

    @set_ev_cls(ofp_event,EventOFPPackentIn, MAIN_DISPATCHER)
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

        # --- Collect features and save to CSV ---
        self._extract_and_save(msg, datapath, eth, pkt)

        # --- Decide output port ---
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # --- Install proactive flow for known destinations ---
        if out_port != ofproto.OFPP_FLOOD:
            if eth.ethertype == ether_types.ETH_TYPE_IP:
                ip = pkt.get_protocol(ipv4.ipv4)
                srcip = ip.src
                dstip = ip.dst
                protocol = ip.proto

                if protocol == in_proto.IPPROTO_ICMP:
                    t = pkt.get_protocol(icmp.icmp)
                    match = parser.OFPMatch(
                        eth_type=ether_types.ETH_TYPE_IP,
                        ipv4_src=srcip, ipv4_dst=dstip,
                        ip_proto=protocol,
                        icmpv4_code=t.code, icmpv4_type=t.type)

                elif protocol == in_proto.IPPROTO_TCP:
                    t = pkt.get_protocol(tcp.tcp)
                    match = parser.OFPMatch(
                        eth_type=ether_types.ETH_TYPE_IP,
                        ipv4_src=srcip, ipv4_dst=dstip,
                        ip_proto=protocol,
                        tcp_src=t.src_port, tcp_dst=t.dst_port,
                        tcp_flags=t.bits)

                elif protocol == in_proto.IPPROTO_UDP:
                    u = pkt.get_protocol(udp.udp)
                    match = parser.OFPMatch(
                        eth_type=ether_types.ETH_TYPE_IP,
                        ipv4_src=srcip, ipv4_dst=dstip,
                        ip_proto=protocol,
                        udp_src=u.src_port, udp_dst=u.dst_port)
                else:
                    match = parser.OFPMatch(
                        eth_type=ether_types.ETH_TYPE_IP,
                        ipv4_src=srcip, ipv4_dst=dstip,
                        ip_proto=protocol)

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

