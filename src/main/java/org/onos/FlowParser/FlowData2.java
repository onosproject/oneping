package org.onos.FlowParser;
/*
 * Copyright 2019-present Open Networking Foundation
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



import org.onlab.packet.Ethernet;
import org.onlab.packet.IPv4;
import org.onlab.packet.TCP;
import org.onos.FlowParser.*;
import org.onosproject.net.flow.FlowId;
import org.onosproject.net.packet.PacketContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Arrays;

import org.onos.FlowDetector.FlowKey;

/**
 * FlowData, represents the relevant features of a flow
 */
public class FlowData2 {
    private static final Logger log = LoggerFactory.getLogger(FlowData.class);

    /**
     * Constants
     */
    static final int IP_TCP = 6;
    static final int IP_UDP = 17;

    static final int P_FORWARD = 0;
    static final int P_BACKWARD = 1;

    static final int ADD_SUCCESS = 0;
    static final int ADD_CLOSED = 1;
    static final int ADD_IDLE = 2;

    /**
     * Configurables
     */
    static final int FLOW_TIMEOUT = 600000000;
    static final int IDLE_THRESHOLD = 1000000;

    /**
     * Features indexes
     */
    //Network-Identifiers Attributes
    static final int FLOW_ID = 1; // Flow ID
    static final int SRC_IP = 2; // Source IP
    static final int SRC_PORT = 3; // Source Port
    static final int DST_IP = 4; // Destination IP
    static final int DST_PORT = 5; // Destination Port
    static final int PROTOCOL = 6; // Protocol
    static final int TIMESTAMP = 7; // Timestamp
    //Byte-Based Attributes
    static final int FWD_HDR_LEN = 8; // Total forward header length
    static final int BWD_HDR_LEN = 9; // Total backward header length
    //Packet-Based Attributes
    static final int TOTAL_FWD_PKTS = 10; // Total forward packets
    static final int TOTAL_BWD_PKTS = 11; // Total backward packets
    static final int TOTAL_LEN_FWD_PKTS = 12; // Total size forward packet
    static final int TOTAL_LEN_BWD_PKTS = 13; // Total size backward packet
    static final int FWD_PKT_LEN = 14; // Min, Mean, Max and SV of forward packet size
    static final int BWD_PKT_LEN = 15; // Min, Mean, Max and SV of backward packet size
    static final int PKT_LEN = 16; // Min, Mean, Max and SV of packet size
    static final int PKT_SIZE_AVG = 17; // Average packet size
    //Interarrival Times Attributes
    static final int DURATION = 18; // Duration of the flow
    static final int FLOW_IAT = 19; // Min, Mean, Max and SV of the time between two packets sent in the flow
    static final int FWD_IAT = 20; // Min, Mean, Max and SV of the time between two packets sent in the fwd direction
    static final int BWD_IAT = 21; // Min, Mean, Max and SV of the time between two packets sent in the bwd direction
    //Flow Timers Attributes
    static final int ACTIVE = 22; // Min, Mean, Max and SV of the time flow was active before becoming idle
    static final int IDLE = 23; // Min, Mean, Max and SV of the time flow was idle before becoming active
    //Flag Based Attributes
    static final int FWD_PSH_FLAGS = 24; // Number of packets with the PSH flag set in the foward direction
    static final int BWD_PSH_FLAGS = 25; // Number of packets with the PSH flag set in the backward direction
    static final int FWD_URG_FLAGS = 26; // Number of packets with the URG flag set in the foward direction
    static final int BWD_URG_FLAGS = 27; // Number of packets with the URG flag set in the backward direction
    static final int FIN_FLAG_COUNT = 28; // Number of packets with FIN flag set
    static final int SYN_FLAG_COUNT = 29; // Number of packets with SYN flag set
    static final int RST_FLAG_COUNT = 30; // Number of packets with RST flag set
    static final int PSH_FLAG_COUNT = 31; // Number of packets with PSH flag set
    static final int ACK_FLAG_COUNT = 32; // Number of packets with ACK flag set
    static final int URG_FLAG_COUNT = 33; // Number of packets with URG flag set
    static final int CWE_FLAG_COUNT = 34; // Number of packets with CWE flag set
    static final int ECE_FLAG_COUNT = 35; // Number of packets with ECE flag set
    //Flow-Based Attributes
    /* FALTA COMPLETAR */
    //Subflow-Based Attributes
    static final int SUBFLOW_FWD_PKTS = 36; // Number of packets in the forward direction
    static final int SUBFLOW_FWD_BYTES = 37; // Number of bytes in the forward direction
    static final int SUBFLOW_BWD_PKTS = 38; // Number of packets in the backward direction
    static final int SUBFLOW_BWD_BYTES = 39; // Number of bytes in the backward direction
    //Number of features
    static final int NUM_FEATURES = 40;



    /**
     * Properties
     */
    public IFlowFeature[] f; // A map of the features to be exported
    public boolean valid; // Has the flow met the requirements of a bi-directional flow
    public long activeStart; // The starting time of the latest activity
    public long timestamp; // Timestamp
    public long firstTime; // The time of the first packet in the flow
    public long flast; // The time of the last packet in the forward direction
    public long blast; // The time of the last packet in the backward direction
    public TcpState cstate; // Connection state of the client
    public TcpState sstate; // Connection state of the server
    public boolean hasData; // Whether the connection has had any data transmitted.
    public boolean isBidir; // Is the flow bi-directional?
    public short pdir; // Direction of the current packet
    public int srcIP; // IP address of the source (client)
    public int srcPort; // Port number of the source connection
    public int dstIP; // IP address of the destination (server)
    public int dstPort; // Port number of the destination connection.
    public byte proto; // The IP protocol being used for the connection.
    public byte dscp; // The first set DSCP field for the flow.
    public FlowKey forwardKey;
    public FlowKey backwardKey;

    public FlowData2(int srcIP, int srcPort, int dstIP, int dstPort, byte proto, Ethernet packet, PacketContext context) {
        this.forwardKey = new FlowKey(srcIP, srcPort, dstIP, dstPort, proto);
        this.backwardKey = new FlowKey(dstIP, dstPort, srcIP, srcPort, proto);
        this.f = new IFlowFeature[NUM_FEATURES];
        this.valid = false;
        //Network-Identifiers Attributes
        IPv4 ipv4 = (IPv4) packet.getPayload();
        TCP tcp = (TCP) ipv4.getPayload();
        this.srcIP = srcIP;
        this.srcPort = srcPort;
        this.dstIP = dstIP;
        this.dstPort = dstPort;
        this.proto = proto;
        this.timestamp = context.time();
        this.f[FLOW_ID] = new ValueFlowFeature(0);
        this.f[SRC_IP] = new ValueFlowFeature(0);
        this.f[SRC_PORT] = new ValueFlowFeature(0);
        this.f[DST_IP] = new ValueFlowFeature(0);
        this.f[DST_PORT] = new ValueFlowFeature(0);
        this.f[PROTOCOL] = new ValueFlowFeature(0);
        this.f[TIMESTAMP] = new ValueFlowFeature(0);
        //Byte-Based Attributes
        this.f[FWD_HDR_LEN] = new ValueFlowFeature(0);
        this.f[BWD_HDR_LEN] = new ValueFlowFeature(0);
        //Packet-Based Attributes

     }
    public int Add(Ethernet packet, int srcIP) {
        long now = System.currentTimeMillis() / 1000;
        long last = getLastTime();
        long diff = now - last;
        // If difference between the last packet and the current packet is greater than the timeout,
        // then the flow is considered inactive.
        if (diff > FLOW_TIMEOUT) {
            return ADD_IDLE;
        }
        // If the flow is not inactive and
        if (now < last) { //if now is less than last
            log.info("Flow: ignoring reordered packet. {} < {}\n", now, last); //
            return ADD_SUCCESS; //return success
        }

        return ADD_SUCCESS;
    }

    private long getLastTime() {
        if (blast == 0) {
            return flast;
        }
        if (flast == 0) {
            return blast;
        }
        return Math.max(flast, blast);
    }

    public void Export() {
        log.info("Exporting flow: " + forwardKey.toString());
        StringBuilder exported = new StringBuilder("\nFlow-data:\n");
        for (int i = 1; i < 10; i++) {
            exported.append(String.format("F%s: %s, ", i, f[i].Export()));
        }
        log.info(exported.toString());
    }

    public boolean IsClosed(){
        return cstate.getState() == TcpState.State.CLOSED && sstate.getState() == TcpState.State.CLOSED;
    }
}