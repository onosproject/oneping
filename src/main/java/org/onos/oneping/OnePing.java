/*
 * Copyright 2015 Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.onos.oneping;


import com.google.common.collect.HashMultimap;
import org.onlab.packet.*;
import org.onos.FlowDetector.FlowKey;
import org.onos.FlowParser.FlowData;
import org.onos.FlowParser.FlowData2;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.DeviceId;
import org.onosproject.net.flow.*;
import org.onosproject.net.flow.criteria.PiCriterion;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.pi.model.PiActionId;
import org.onosproject.net.pi.model.PiMatchFieldId;
import org.onosproject.net.pi.model.PiTableId;
import org.onosproject.net.pi.runtime.PiAction;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


import java.nio.charset.StandardCharsets;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.Flow;

/**
 * Sample application that permits only one ICMP ping per minute for a unique
 * src/dst MAC pair per switch.
 */
@SuppressWarnings("ALL")
@Component(immediate = true)
public class OnePing {




    private static Logger log = LoggerFactory.getLogger(OnePing.class);

    private static final String MSG_PINGED_ONCE =
            "Thank you, Vasili. One ping from {} to {} received by {}";
    private static final String MSG_PINGED_TWICE =
            "What are you doing, Vasili?! I said one ping only!!! " +
                    "Ping from {} to {} has already been received by {};" +
                    " 60 second ban has been issued";
    private static final String MSG_PING_REENABLED =
            "Careful next time, Vasili! Re-enabled ping from {} to {} on {}";


    private static final int PRIORITY = 128;
    private static final int DROP_PRIORITY = 129;
    private static final int TIMEOUT_SEC = 60; // seconds

    private static final int SECONDS = 1000;



    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    private ApplicationId appId;
    private final PacketProcessor packetProcessor = new SdnPacketProcessor();

    // Selector for ICMP traffic that is to be intercepted
    PiCriterion intercept = PiCriterion.builder()
            .matchTernary(PiMatchFieldId.of("hdr.ethernet.ether_type"), Ethernet.TYPE_IPV4, 0xffff)
            .matchTernary(PiMatchFieldId.of("hdr.ipv4.protocol"), IPv4.PROTOCOL_ICMP, 0xff)
            .build();

    // Means to track detected pings from each device on a temporary basis
    private final HashMultimap<DeviceId, PingRecord> pings = HashMultimap.create();
    private final Timer timer = new Timer("oneping-sweeper");
    // Holds the current active flows
    private HashMap<FlowKey, FlowData> flows = new HashMap<FlowKey, FlowData>();

    @Activate
    public void activate() {
        appId = coreService.registerApplication("org.onosproject.oneping",
                                                () -> log.info("Periscope down."));
        packetService.addProcessor(packetProcessor, PRIORITY);
        packetService.requestPackets(DefaultTrafficSelector.builder().matchPi(intercept).build(),
                                     PacketPriority.CONTROL, appId, Optional.empty());
        log.info(appId.toString());
        log.info("Started");
    }

    @Deactivate
    public void deactivate() {
        packetService.removeProcessor(packetProcessor);
        flows.clear();
        flowRuleService.removeFlowRulesById(appId);
        log.info("Stopped");
    }


    // Processes the specified ICMP ping packet.
    private void processPing(PacketContext context, Ethernet eth) {
        DeviceId deviceId = context.inPacket().receivedFrom().deviceId();
        MacAddress src = eth.getSourceMAC();
        MacAddress dst = eth.getDestinationMAC();
        PingRecord ping = new PingRecord(src, dst);
        boolean pinged = pings.get(deviceId).contains(ping);

        if (pinged) {
            // Two pings detected; ban further pings and block packet-out
            log.warn(MSG_PINGED_TWICE, src, dst, deviceId);
            banPings(deviceId, src, dst);
            context.block();
        } else {
            // One ping detected; track it for the next minute
            log.info(MSG_PINGED_ONCE, src, dst, deviceId);
            pings.put(deviceId, ping);
            timer.schedule(new PingPruner(deviceId, ping), TIMEOUT_SEC * 1000);
        }
    }

    // Installs a drop rule for the ICMP pings between given src/dst.
    private void banPings(DeviceId deviceId, MacAddress src, MacAddress dst) {
        PiCriterion match = PiCriterion.builder()
                .matchTernary(PiMatchFieldId.of("hdr.ethernet.ether_type"), Ethernet.TYPE_IPV4, 0xffff)
                .matchTernary(PiMatchFieldId.of("hdr.ipv4.protocol"), IPv4.PROTOCOL_ICMP, 0xff)
                .matchTernary(PiMatchFieldId.of("hdr.ethernet.src_addr"), src.toLong(), 0xffffffffffffL)
                .matchTernary(PiMatchFieldId.of("hdr.ethernet.dst_addr"), dst.toLong(), 0xffffffffffffL)
                .build();

        PiAction action = PiAction.builder()
                .withId(PiActionId.of("ingress.table0_control.drop"))
                .build();

        FlowRule dropRule = DefaultFlowRule.builder()
                .forDevice(deviceId).fromApp(appId).makePermanent().withPriority(DROP_PRIORITY)
                .forTable(PiTableId.of("ingress.table0_control.table0"))
                .withSelector(DefaultTrafficSelector.builder().matchPi(match).build())
                .withTreatment(DefaultTrafficTreatment.builder().piTableAction(action).build())
                .build();

        // Apply the drop rule...
        flowRuleService.applyFlowRules(dropRule);

        // Schedule the removal of the drop rule after a minute...
        timer.schedule(new TimerTask() {
            @Override
            public void run() {
                flowRuleService.removeFlowRules(dropRule);
                log.warn(MSG_PING_REENABLED, src, dst, deviceId);
            }
        }, 60 * SECONDS);
    }

    private void createFlowRule(DeviceId deviceId, MacAddress src, MacAddress dst) {

        PiCriterion match = PiCriterion.builder()
                .matchTernary(PiMatchFieldId.of("hdr.ethernet.ether_type"), Ethernet.TYPE_IPV4, 0xffff)
                .matchTernary(PiMatchFieldId.of("hdr.ipv4.protocol"), IPv4.PROTOCOL_TCP, 0xff)
                .matchTernary(PiMatchFieldId.of("hdr.ethernet.src_addr"), src.toLong(), 0xffffffffffffL)
                .matchTernary(PiMatchFieldId.of("hdr.ethernet.dst_addr"), dst.toLong(), 0xffffffffffffL)
                .build();

        FlowRule flowRule = DefaultFlowRule.builder()
                .forDevice(deviceId).fromApp(appId).makePermanent().withPriority(PRIORITY)
                .forTable(PiTableId.of("ingress.table0_control.table0"))
                .withSelector(DefaultTrafficSelector.builder().matchPi(match).build())
                .build();

        //Create the flow rule
        flowRuleService.applyFlowRules(flowRule);

        timer.schedule(new TimerTask() {
            @Override
            public void run() {
                flowRuleService.removeFlowRules(flowRule);
            }
        }, 10 * SECONDS);

    }

    //PROCESS ANY PACKET
    private void processTCP(PacketContext context, Ethernet eth) {
        // Get identifiers of the packet
        DeviceId deviceId = context.inPacket().receivedFrom().deviceId();
        IPv4 ipv4 = (IPv4) eth.getPayload();
        int srcIP = ipv4.getSourceAddress();
        int dstIP = ipv4.getDestinationAddress();
        byte proto = ipv4.getProtocol();
        TCP tcp = (TCP) ipv4.getPayload();
        int srcPort = tcp.getSourcePort();
        int dstPort = tcp.getDestinationPort();

        // Calculate forward and backward keys
        FlowKey forwardKey = new FlowKey(srcIP, srcPort, dstIP, dstPort, proto);
        FlowKey backwardKey = new FlowKey(dstIP, dstPort, srcIP, srcPort, proto);
        FlowData f;


        // Check if flow is stored
        if (flows.containsKey(forwardKey) || flows.containsKey(backwardKey)) {
            // Get corresponding flow and update it
            if (flows.containsKey(forwardKey)) {
                f = flows.get(forwardKey);
            } else {
                f = flows.get(backwardKey);
            }
            f.Add(eth, srcIP);
            // Calling export will generate a log of the updated flow features
            //f.Export();

            // log.info("Updating flow, Key(srcIP: {}, srcPort: {}, dstIP: {}, dstPort: {}, proto: {})", f.srcIP, f.srcPort, f.dstIP, f.dstPort, f.proto);
        } else {
            // Add new flow
            f = new FlowData(srcIP, srcPort, dstIP, dstPort, proto, eth);
            // Include forward and backward keys
            flows.put(forwardKey, f);
            flows.put(backwardKey, f);
            // log.info("Added new flow, Key(srcIP: {}, srcPort: {}, dstIP: {}, dstPort: {}, proto: {})", srcIP, srcPort, dstIP, dstPort, proto);
        }
        if(f.IsClosed()){
            log.info("FLOW IS CLOSED. Device: {}", deviceId);
            f.Export();
        }
    }

        // Processes the specified TCP packet
    /*private niPacket processTCP(PacketContext context, Ethernet eth) {
        // Get protocol
        String protocol = "TCP";
        //Get time of received packet
        long timestamp = context.time();
        //Get DeviceId, src MAC, dst MAC from eth packet
        DeviceId deviceId = context.inPacket().receivedFrom().deviceId();
        MacAddress srcMAC = eth.getSourceMAC();
        MacAddress dstMAC = eth.getDestinationMAC();
        //Get IP header
        IPv4 ipv4 = (IPv4) eth.getPayload();
        //Get Source and Destination IP
        String srcIP = ipv4.fromIPv4Address(ipv4.getSourceAddress());
        String dstIP = ipv4.fromIPv4Address(ipv4.getDestinationAddress());
        //Get TCP header
        TCP tcp = (TCP) ipv4.getPayload();
        //Get Source and Destination port
        int srcPort = tcp.getSourcePort();
        int dstPort = tcp.getDestinationPort();
        //Get TCP Data
        Data data = (Data) tcp.getPayload();
        byte[] dataBytes = data.getData();
        String s = new String(dataBytes, StandardCharsets.UTF_8);
        //Get different values
        int srcIP = ipv4.getSourceAddress();
        int dstIP = ipv4.getDestinationAddress();
        int srcPort = tcp.getSourcePort();
        int dstPort = tcp.getDestinationPort();
        byte proto = ipv4.getProtocol();


        // Calculate forward and backward keys
        FlowKey forwardKey = new FlowKey(srcIP, srcPort, dstIP, dstPort, proto);
        FlowKey backwardKey = new FlowKey(dstIP, dstPort, srcIP, srcPort, proto);
        FlowData f;
        FlowData2 f2;
        f2 = new FlowData2(srcIP, srcPort, dstIP, dstPort, proto, eth, context);
        f2.Export();
        String flowId = forwardKey.toString();

        if(flows.containsKey(forwardKey) || flows.containsKey(backwardKey)){
            // Get corresponding flow and update it
            if(flows.containsKey(forwardKey)){
                f = flows.get(forwardKey);
            }else{
                f = flows.get(backwardKey);
            }
            f.Add(eth, srcIP);
            // Calling export will generate a log of the updated flow features
            //f.Export();

            //log.info("Updating flow, Key(srcIP: {}, srcPort: {}, dstIP: {}, dstPort: {}, proto: {})", ipv4.fromIPv4Address(f.srcIP),f.srcPort, ipv4.fromIPv4Address(f.dstIP), f.dstPort, f.proto);
        } else {
            // Add new flow
            f = new FlowData(srcIP, srcPort, dstIP, dstPort, proto, eth);
            // Include forward and backward keys
            flows.put(forwardKey, f);
            flows.put(backwardKey, f);
            log.info("Added new flow, Key(srcIP: {}, srcPort: {}, dstIP: {}, dstPort: {}, proto: {})", ipv4.fromIPv4Address(srcIP),
                    srcPort, ipv4.fromIPv4Address(dstIP), dstPort, proto);
        }


        niPacket niPacket= new niPacket(deviceId,flowId,srcIP,dstIP,srcPort,dstPort,protocol, timestamp);

        log.info(niPacket.toString());

        if(f.IsClosed()){
            log.info("FLOW IS CLOSED");
            f.Export();
        }

        return niPacket;

        //Get TCP flags
        log.info(MSG_TCP_PACKET, srcMAC, dstMAC, srcIP, dstIP, srcPort, dstPort, deviceId);

        //Print all tcp header fields
        log.info(MSG_TCP_HEADER, tcp.getSourcePort(), tcp.getDestinationPort(), tcp.getSequence(),
                tcp.getAcknowledge(), tcp.getDataOffset(), tcp.getFlags(), tcp.getWindowSize(),
                tcp.getChecksum(), tcp.getUrgentPointer(), tcp.getOptions());

        //Print tcp data
        log.info(MSG_TCP_DATA, s);

    }*/

    private niPacket processICMP(PacketContext context, Ethernet eth) {
        // Get protocol
        String protocol = "ICMP";
        //FlowID
        String flowId = "12345";
        //Iterable<FlowEntry> flowEntries = getFlowEntries(context.inPacket().receivedFrom().deviceId());
        //log.info("FLOW ENTRIES: {}", flowEntries);
        //Get time of received packet
        long timestamp = context.time();
        //Get DeviceId, src MAC, dst MAC from eth packet
        DeviceId deviceId = context.inPacket().receivedFrom().deviceId();
        MacAddress srcMAC = eth.getSourceMAC();
        MacAddress dstMAC = eth.getDestinationMAC();
        //Get IP header
        IPv4 ipv4 = (IPv4) eth.getPayload();
        //Get Source and Destination IP
        String srcIP = ipv4.fromIPv4Address(ipv4.getSourceAddress());
        String dstIP = ipv4.fromIPv4Address(ipv4.getDestinationAddress());
        //Get ICMP header
        ICMP icmp = (ICMP) ipv4.getPayload();
        //cookie
        //Get ICMP type and code
        int type = icmp.getIcmpType();
        //transform type to string and append to protocol
        protocol = protocol + " " + (type==0?"EchoReply":type==8?"EchoRequest":type==8?"Redirect":"Time Exceeded");

        niPacket niPacket= new niPacket(deviceId,flowId,srcIP,dstIP,0,0,protocol, timestamp);
        return niPacket;
    }


    // Indicates whether the specified packet corresponds to ICMP ping.
    private boolean isIcmpPing(Ethernet eth) {
        return eth.getEtherType() == Ethernet.TYPE_IPV4 &&
                ((IPv4) eth.getPayload()).getProtocol() == IPv4.PROTOCOL_ICMP;
    }
    private boolean isTCP(Ethernet eth) {
        return eth.getEtherType() == Ethernet.TYPE_IPV4 &&
                ((IPv4) eth.getPayload()).getProtocol() == IPv4.PROTOCOL_TCP;
    }

    // Gets flow entries of given device
    private Iterable<FlowEntry> getFlowEntries(DeviceId deviceId) {

        // Use of getFlowEntries()
        Iterable<FlowEntry> flowEntries = flowRuleService.getFlowEntries(deviceId);
        for (FlowEntry flowEntry : flowEntries) {
            log.info("Flow entry: {}", flowEntry);
            FlowId flowId = flowEntry.id();
            log.info("Flow ID: {}", flowId);
        }

        return flowRuleService.getFlowEntries(deviceId);
    }

    // Intercepts packets
    private class SdnPacketProcessor implements PacketProcessor {
        @Override
        public void process(PacketContext context) {
            //Get Ethernet header
            Ethernet eth = context.inPacket().parsed();
            if (isIcmpPing(eth)) {
                niPacket niPacket = processICMP(context, eth);
                log.info("ICMP packet: {}", niPacket.toString());
            }
            else if (isTCP(eth)) {
                processTCP(context, eth);
            }
        }
    }


    // Class packet with Flow-id, Src-IP, Dst-IP, Src-Port, Dst-Port, Protocol-Type, Timestamp
    private class niPacket {
        private DeviceId deviceID;
        private String flowId;
        private String srcIP;
        private String dstIP;
        private int srcPort;
        private int dstPort;
        private String protocol;
        private long timestamp;

        public niPacket(DeviceId deviceID, String flowId, String srcIP, String dstIP, int srcPort, int dstPort, String protocol, long timestamp) {
            this.deviceID = deviceID;
            this.flowId = flowId;
            this.srcIP = srcIP;
            this.dstIP = dstIP;
            this.srcPort = srcPort;
            this.dstPort = dstPort;
            this.protocol = protocol;
            this.timestamp = timestamp;
        }

        public DeviceId getDeviceID() {
            return deviceID;
        }

        public String getFlowId() {
            return flowId;
        }

        public String getsrcIP() {
            return srcIP;
        }

        public String getdstIP() {
            return dstIP;
        }

        public int getsrcPort() {
            return srcPort;
        }

        public int getdstPort() {
            return dstPort;
        }

        public String getProtocol() {
            return protocol;
        }

        public long getTimestamp() {
            return timestamp;
        }

        @Override
        public String toString() {
            Date date = new Date(timestamp);
            DateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
            return "Packet{" +
                    "deviceID='" + deviceID + '\'' +
                    ", flowId='" + flowId + '\'' +
                    ", srcIP='" + srcIP + '\'' +
                    ", dstIP='" + dstIP + '\'' +
                    ", srcPort=" + srcPort +
                    ", dstPort=" + dstPort +
                    ", protocol='" + protocol + '\'' +
                    ", timestamp=" + df.format(date) +
                    '}';

        }
    }

    // Record of a ping between two end-station MAC addresses
    private class PingRecord {
        private final MacAddress src;
        private final MacAddress dst;

        PingRecord(MacAddress src, MacAddress dst) {
            this.src = src;
            this.dst = dst;
        }

        @Override
        public int hashCode() {
            return Objects.hash(src, dst);
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj == null || getClass() != obj.getClass()) {
                return false;
            }
            final PingRecord other = (PingRecord) obj;
            return Objects.equals(this.src, other.src) && Objects.equals(this.dst, other.dst);
        }
    }

    // Prunes the given ping record from the specified device.
    private class PingPruner extends TimerTask {
        private final DeviceId deviceId;
        private final PingRecord ping;

        public PingPruner(DeviceId deviceId, PingRecord ping) {
            this.deviceId = deviceId;
            this.ping = ping;
        }

        @Override
        public void run() {
            pings.remove(deviceId, ping);
        }
    }

}
