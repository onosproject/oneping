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
import org.onlab.packet.Ethernet;
import org.onlab.packet.IPv4;
import org.onlab.packet.MacAddress;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.DeviceId;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleService;
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

import java.util.Objects;
import java.util.Optional;
import java.util.Timer;
import java.util.TimerTask;

/**
 * Sample application that permits only one ICMP ping per minute for a unique
 * src/dst MAC pair per switch.
 */
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
    private final PacketProcessor packetProcessor = new PingPacketProcessor();

    // Selector for ICMP traffic that is to be intercepted
    PiCriterion intercept = PiCriterion.builder()
            .matchTernary(PiMatchFieldId.of("hdr.ethernet.ether_type"), Ethernet.TYPE_IPV4, 0xffff)
            .matchTernary(PiMatchFieldId.of("hdr.ipv4.protocol"), IPv4.PROTOCOL_ICMP, 0xff)
            .build();

    // Means to track detected pings from each device on a temporary basis
    private final HashMultimap<DeviceId, PingRecord> pings = HashMultimap.create();
    private final Timer timer = new Timer("oneping-sweeper");

    @Activate
    public void activate() {
        appId = coreService.registerApplication("org.onosproject.oneping",
                                                () -> log.info("Periscope down."));
        packetService.addProcessor(packetProcessor, PRIORITY);
        packetService.requestPackets(DefaultTrafficSelector.builder().matchPi(intercept).build(),
                                     PacketPriority.CONTROL, appId, Optional.empty());
        log.info("Started");
    }

    @Deactivate
    public void deactivate() {
        packetService.removeProcessor(packetProcessor);
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

    // Indicates whether the specified packet corresponds to ICMP ping.
    private boolean isIcmpPing(Ethernet eth) {
        return eth.getEtherType() == Ethernet.TYPE_IPV4 &&
                ((IPv4) eth.getPayload()).getProtocol() == IPv4.PROTOCOL_ICMP;
    }


    // Intercepts packets
    private class PingPacketProcessor implements PacketProcessor {
        @Override
        public void process(PacketContext context) {
            Ethernet eth = context.inPacket().parsed();
            if (isIcmpPing(eth)) {
                processPing(context, eth);
            }
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
