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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;

import org.onos.FlowDetector.FlowKey;

/**
 * FlowData, represents the relevant features of a flow
 */
public class FlowData {
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
     * NEW features
     */



    /**
     * Features indexes
     */
    //Byte-Based Attributes
    static final int FWD_HDR_LEN = 0; // Total forward header length
    static final int BWD_HDR_LEN = 1; // Total backward header length
    // Packet-Based Attributes
    static final int TOTAL_FWD_PKTS = 2; // Total forward packets
    static final int TOTAL_LEN_FWD_PKTS = 3; // Total forward size
    static final int TOTAL_BWD_PKTS = 4; // Total backward packets
    static final int TOTAL_LEN_BWD_PKTS = 5; //Total backward size
    static final int FWD_PKT_LEN = 6; // Forward packets length
    static final int BWD_PKT_LEN = 7; // Backward packets length
    static final int PKT_LEN = 8; // Total packets length *Not implemented*
    static final int PKT_SIZE_AVG = 9; // Average packet size *Not implemented*
    // Interarrival Times Attributes
    static final int FLOW_IAT = 10; // Flow interarrival time *Not implemented*
    static final int FWD_IAT = 11; // Forward interarrival time
    static final int BWD_IAT = 12; // Backward interarrival time
    static final int DURATION = 13; // Duration of the flow
    // Flow Timers Attributes
    static final int ACTIVE = 14; // Active time before coming idle
    static final int IDLE = 15; // Idle time before coming active
    // Flag-Based Attributes
    static final int FWD_PSH_FLAGS = 16; // Forward PSH count
    static final int BWD_PSH_FLAGS = 17; // Backward PSH count
    static final int FWD_URG_FLAGS = 18; // Forward URG count
    static final int BWD_URG_FLAGS = 19; // Backward URG count
    // Subflow-Based Attributes
    static final int SUBFLOW_FWD_PKTS = 20; // Total Sub-flow forward packets
    static final int SUBFLOW_FWD_BYTES = 21; // Total Sub-flow forward bytes
    static final int SUBFLOW_BWD_PKTS = 22; // Total Sub-flow backward packets
    static final int SUBFLOW_BWD_BYTES= 23; // Total Sub-flow backward bytes

    //Number of features
    static final int NUM_FEATURES = 24; // Number of features

    /**
     * Properties
     */

    //Network-Identifiers Attributes

    public String flowId; // Flow ID
    public int srcIP; // IP address of the source (client)
    public int srcPort; // Port number of the source connection
    public int dstIP; // IP address of the destination (server)
    public int dstPort; // Port number of the destination connection.
    public byte proto; // The IP protocol being used for the connection.
    public long timestamp; // Timestamp of flow
    //
    public IFlowFeature[] f; // A map of the features to be exported
    public boolean valid; // Has the flow met the requirements of a bi-directional flow
    public long activeStart; // The starting time of the latest activity
    public long firstTime; // The time of the first packet in the flow
    public long flast; // The time of the last packet in the forward direction
    public long blast; // The time of the last packet in the backward direction
    public TcpState cstate; // Connection state of the client
    public TcpState sstate; // Connection state of the server
    public boolean hasData; // Whether the connection has had any data transmitted.
    public boolean isBidir; // Is the flow bi-directional?
    public short pdir; // Direction of the current packet
    public byte dscp; // The first set DSCP field for the flow.
    public FlowKey forwardKey;
    public FlowKey backwardKey;

    public FlowData(int srcIP, int srcPort, int dstIP, int dstPort, byte proto, Ethernet packet) {
        this.forwardKey = new FlowKey(srcIP, srcPort, dstIP, dstPort, proto);
        this.backwardKey = new FlowKey(dstIP, dstPort, srcIP, srcPort, proto);
        this.f = new IFlowFeature[NUM_FEATURES];
        this.valid = false;
        //Network-Identifiers Attributes
        IPv4 ipv4 = (IPv4) packet.getPayload();
        TCP tcp = (TCP) ipv4.getPayload();
        FlowKey key = new FlowKey(srcIP, srcPort, dstIP, dstPort, proto);
        this.flowId = key.toString();
        this.srcIP = srcIP;
        this.srcPort = srcPort;
        this.dstIP = dstIP;
        this.dstPort = dstPort;
        this.proto = proto;
        this.dscp = ipv4.getDscp();
        // Byte-Based Attributes
        this.f[FWD_HDR_LEN] = new ValueFlowFeature(0);
        this.f[BWD_HDR_LEN] = new ValueFlowFeature(0);
        // Packet-Based Attributes
        this.f[TOTAL_FWD_PKTS] = new ValueFlowFeature(0);
        this.f[TOTAL_LEN_FWD_PKTS] = new ValueFlowFeature(0);
        this.f[TOTAL_BWD_PKTS] = new ValueFlowFeature(0);
        this.f[TOTAL_LEN_BWD_PKTS] = new ValueFlowFeature(0);
        this.f[FWD_PKT_LEN] = new DistributionFlowFeature(0);
        this.f[BWD_PKT_LEN] = new DistributionFlowFeature(0);
        this.f[PKT_LEN] = new DistributionFlowFeature(0);
        this.f[PKT_SIZE_AVG] = new ValueFlowFeature(0);
        // Interarrival Times Attributes
        this.f[FLOW_IAT] = new DistributionFlowFeature(0);
        this.f[FWD_IAT] = new DistributionFlowFeature(0);
        this.f[BWD_IAT] = new DistributionFlowFeature(0);
        this.f[DURATION] = new ValueFlowFeature(0);
        // Flow Timers Attributes
        this.f[ACTIVE] = new DistributionFlowFeature(0);
        this.f[IDLE] = new DistributionFlowFeature(0);
        // Flag-based Attributes
        this.f[FWD_PSH_FLAGS] = new ValueFlowFeature(0);
        this.f[BWD_PSH_FLAGS] = new ValueFlowFeature(0);
        this.f[FWD_URG_FLAGS] = new ValueFlowFeature(0);
        this.f[BWD_URG_FLAGS] = new ValueFlowFeature(0);
        // Subflow-based Attributes
        this.f[SUBFLOW_FWD_PKTS] = new ValueFlowFeature(0);
        this.f[SUBFLOW_FWD_BYTES] = new ValueFlowFeature(0);
        this.f[SUBFLOW_BWD_PKTS] = new ValueFlowFeature(0);
        this.f[SUBFLOW_BWD_BYTES] = new ValueFlowFeature(0);
        // ---------------------------------------------------------
        this.f[TOTAL_FWD_PKTS].Set(1);
        long length = ipv4.getTotalLength();
        short flags = tcp.getFlags();
        this.f[TOTAL_LEN_FWD_PKTS].Set(length);
        this.f[FWD_PKT_LEN].Add(length);
        this.firstTime = System.currentTimeMillis();
        this.flast = this.firstTime;
        this.activeStart = this.firstTime;
        if (this.proto == IPv4.PROTOCOL_TCP) {
            // TCP specific code:
            this.cstate = new TcpState(TcpState.State.START);
            this.sstate = new TcpState(TcpState.State.START);
            if (TcpState.tcpSet(TcpState.TCP_PUSH, flags)) {
                this.f[FWD_PSH_FLAGS].Set(1);
            }
            if (TcpState.tcpSet(TcpState.TCP_URG, flags)) {
                this.f[FWD_URG_FLAGS].Set(1);
            }
        }
        long headerLength = ipv4.getHeaderLength()*32/8;
        this.f[FWD_HDR_LEN].Set(headerLength);


        this.hasData = false;
        this.pdir = P_FORWARD;
        this.updateStatus(packet);
    }

    public boolean IsClosed(){
        return cstate.getState() == TcpState.State.CLOSED && sstate.getState() == TcpState.State.CLOSED;
    }

    public int Add(Ethernet packet, int srcIP) {
        //get timestamp packet
        long now = System.currentTimeMillis(); //obtain actual time
        long last = getLastTime(); //obtain last time seen packet
        long diff = now - last; //obtain difference between first and last packet
        if (diff > FLOW_TIMEOUT) { //if difference is greater than timeout
            return ADD_IDLE; //return idle (packet set inactive)
        }
        if (now < last) { //if now is less than last
            log.info("Flow: ignoring reordered packet. {} < {}\n", now, last); //
            return ADD_SUCCESS; //return success
        }
        IPv4 ipv4 = (IPv4) packet.getPayload();
        long length = ipv4.getTotalLength(); //obtain length of packet
        long hlen = ipv4.getHeaderLength()*32/8; //obtain header length of packet
        byte flags = ipv4.getFlags(); //obtain flags of packet
        if (now < firstTime) { //if now is less than first time
            log.error("Current packet is before start of flow. {} < {}\n", now, firstTime); // log error
        }
        if (this.srcIP == srcIP) {
            pdir = P_FORWARD;
        } else {
            pdir = P_BACKWARD;
        }
        if (diff > IDLE_THRESHOLD) {
            f[IDLE].Add(diff);
            // Active time stats - calculated by looking at the previous packet
            // time and the packet time for when the last idle time ended.
            diff = last - activeStart;
            f[ACTIVE].Add(diff);

            flast = 0;
            blast = 0;
            activeStart = now;
        }
        if (pdir == P_FORWARD) {
            // Packet is travelling in the forward direction
            // Calculate some statistics
            // Packet length
            f[FWD_PKT_LEN].Add(length);
            f[TOTAL_LEN_FWD_PKTS].Add(length);
            f[TOTAL_FWD_PKTS].Add(1);
            f[FWD_HDR_LEN].Add(hlen);
            // Interarrival time
            if (flast > 0) {
                diff = now - flast;
                f[FWD_IAT].Add(diff);
            }
            if (proto == IP_TCP) {
                // Packet is using TCP protocol
                if (TcpState.tcpSet(TcpState.TCP_PUSH, flags)) {
                    f[FWD_PSH_FLAGS].Add(1);
                }
                if (TcpState.tcpSet(TcpState.TCP_URG, flags)) {
                    f[FWD_URG_FLAGS].Add(1);
                }
                // Update the last forward packet time stamp
            }
            flast = now;
        } else {
            // Packet is travelling in the backward direction
            isBidir = true;
            if (dscp == 0) {
                dscp = ipv4.getDscp();
            }
            // Calculate some statistics
            // Packet length
            f[BWD_PKT_LEN].Add(length);
            f[TOTAL_LEN_BWD_PKTS].Add(length); // Doubles up as c_BWD_PKT_LEN_sum from NM
            f[TOTAL_BWD_PKTS].Add(1);
            f[BWD_HDR_LEN].Add(hlen);
            // Inter-arrival time
            if (blast > 0) {
                diff = now - blast;
                f[BWD_IAT].Add(diff);
            }
            if (proto == IP_TCP) {
                // Packet is using TCP protocol
                if (TcpState.tcpSet(TcpState.TCP_PUSH, flags)) {
                    f[BWD_PSH_FLAGS].Add(1);
                }
                if (TcpState.tcpSet(TcpState.TCP_URG, flags)) {
                    f[BWD_URG_FLAGS].Add(1);
                }
            }
            // Update the last backward packet time stamp
            blast = now;
        }

        // Update the status (validity, TCP connection state) of the flow.
        updateStatus(packet);

        if (proto == IP_TCP &&
                cstate.getState() == TcpState.State.CLOSED &&
                sstate.getState() == TcpState.State.CLOSED) {
            return ADD_CLOSED;
        }
        return ADD_SUCCESS;
    }

    public void Export() {
        if (!valid) {
            log.info("Not valid Flow - Possible attack");
            //return;
        }

        // -----------------------------------
        // First, lets consider the last active time in the calculations in case
        // this changes something.
        // -----------------------------------
        long diff = getLastTime() - activeStart;
        f[ACTIVE].Add(diff);

        // ---------------------------------
        // Update Flow stats which require counters or other final calculations
        // ---------------------------------

        // More sub-flow calculations
        if (f[ACTIVE].Get() > 0) {
            f[SUBFLOW_FWD_PKTS].Set(f[TOTAL_FWD_PKTS].Get() / f[ACTIVE].Get());
            f[SUBFLOW_FWD_BYTES].Set(f[TOTAL_LEN_FWD_PKTS].Get() / f[ACTIVE].Get());
            f[SUBFLOW_BWD_PKTS].Set(f[TOTAL_BWD_PKTS].Get() / f[ACTIVE].Get());
            f[SUBFLOW_BWD_BYTES].Set(f[TOTAL_LEN_BWD_PKTS].Get() / f[ACTIVE].Get());
        }
        f[DURATION].Set(getLastTime() - firstTime);
        if (f[DURATION].Get() < 0) {
            log.error("duration ({}) < 0", f[DURATION]);
        }
        Date date = new Date(firstTime);
        DateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

        StringBuilder exported = new StringBuilder(String.format("\n--Network-Based Attributes--\n" +
                        "Flow-id: %s\n" +
                        "Src-IP: %s\n" +
                        "Src-Port: %d\n" +
                        "Dst-IP: %s\n" +
                        "Dst-Port: %d\n" +
                        "Protocol-Type: %d\n"+
                        "Timestamp: %s\n", flowId,IPv4.fromIPv4Address(srcIP), srcPort,
                IPv4.fromIPv4Address(dstIP), dstPort, proto, df.format(date)));

        exported.append(String.format("\n--Byte-Based Attributes--\n" +
                "Fwd-Header-Len: %d\n" +
                "Bwd-Header-Len: %d\n", f[FWD_HDR_LEN].Get(), f[BWD_HDR_LEN].Get()));

        exported.append(String.format("\n--Packet-Based Attributes--\n" +
                        "Total-Fwd-Pkts: %d\n" +
                        "Total-Bwd-Pkts: %d\n" +
                        "Total-Len-Fwd-Pkts: %d\n" +
                        "Total-Len-Bwd-Pkts: %d\n" +
                        "Fwd-Pkt-Len-Min: %s\n" +
                        "Fwd-Pkt-Len-Mean: %s\n" +
                        "Fwd-Pkt-Len-Max: %s\n" +
                        "Fwd-Pkt-Len-Std: %s\n" +
                        "Bwd-Pkt-Len-Min: %s\n" +
                        "Bwd-Pkt-Len-Mean: %s\n" +
                        "Bwd-Pkt-Len-Max: %s\n" +
                        "Bwd-Pkt-Len-Std: %s\n" +
                        "Pkt-Len-Min: %s\n" +
                        "Pkt-Len-Mean: %s\n" +
                        "Pkt-Len-Max: %s\n" +
                        "Pkt-Len-Std: %s\n" +
                        "Pkt-Size-Avg: %s\n", f[TOTAL_FWD_PKTS].Get(), f[TOTAL_BWD_PKTS].Get(),
                f[TOTAL_LEN_FWD_PKTS].Get(), f[TOTAL_LEN_BWD_PKTS].Get(), f[FWD_PKT_LEN].ToArrayList().get(0),
                f[FWD_PKT_LEN].ToArrayList().get(1), f[FWD_PKT_LEN].ToArrayList().get(2), f[FWD_PKT_LEN].ToArrayList().get(3),
                f[BWD_PKT_LEN].ToArrayList().get(0), f[BWD_PKT_LEN].ToArrayList().get(1), f[BWD_PKT_LEN].ToArrayList().get(2),
                f[BWD_PKT_LEN].ToArrayList().get(3), f[PKT_LEN].ToArrayList().get(0), f[PKT_LEN].ToArrayList().get(1),
                f[PKT_LEN].ToArrayList().get(2), f[PKT_LEN].ToArrayList().get(3), f[PKT_SIZE_AVG]));

        exported.append(String.format("\n--Interarrival Times Attributes--\n" +
                "Duration: %s\n" +
                "Flow-IAT-Min: %s\n" +
                "Flow-IAT-Mean: %s\n" +
                "Flow-IAT-Max: %s\n" +
                "Flow-IAT-Std: %s\n" +
                "Fwd-IAT-Tot: %s\n" +
                "Fwd-IAT-Min: %s\n" +
                "Fwd-IAT-Mean: %s\n" +
                "Fwd-IAT-Max: %s\n" +
                "Fwd-IAT-Std: %s\n" +
                "Bwd-IAT-Tot: %s\n" +
                "Bwd-IAT-Min: %s\n" +
                "Bwd-IAT-Mean: %s\n" +
                "Bwd-IAT-Max: %s\n" +
                "Bwd-IAT-Std: %s\n", f[DURATION].Get(), f[FLOW_IAT].ToArrayList().get(0),
                f[FLOW_IAT].ToArrayList().get(1), f[FLOW_IAT].ToArrayList().get(2), f[FLOW_IAT].ToArrayList().get(3),
                f[FWD_IAT].Get(), f[FWD_IAT].ToArrayList().get(0), f[FWD_IAT].ToArrayList().get(1),
                f[FWD_IAT].ToArrayList().get(2), f[FWD_IAT].ToArrayList().get(3), f[BWD_IAT].Get(),
                f[BWD_IAT].ToArrayList().get(0), f[BWD_IAT].ToArrayList().get(1), f[BWD_IAT].ToArrayList().get(2),
                f[BWD_IAT].ToArrayList().get(3)));

        exported.append(String.format("\n--Flow Timers Attributes--\n" +
                "Active-Time-Min: %s\n" +
                "Active-Time-Mean: %s\n" +
                "Active-Time-Max: %s\n" +
                "Active-Time-Std: %s\n" +
                "Idle-Time-Min: %s\n" +
                "Idle-Time-Mean: %s\n" +
                "Idle-Time-Max: %s\n" +
                "Idle-Time-Std: %s\n", f[ACTIVE].ToArrayList().get(0), f[ACTIVE].ToArrayList().get(1),
                f[ACTIVE].ToArrayList().get(2), f[ACTIVE].ToArrayList().get(3), f[IDLE].ToArrayList().get(0),
                f[IDLE].ToArrayList().get(1), f[IDLE].ToArrayList().get(2), f[IDLE].ToArrayList().get(3)));

        exported.append(String.format("\n--Flag-based Attributes--\n" +
                "Fwd-PSH-Flags: %d\n" +
                "Bwd-PSH-Flags: %d\n" +
                "Fwd-URG-Flags: %d\n" +
                "Bwd-URG-Flags: %d\n", f[FWD_PSH_FLAGS].Get(), f[BWD_PSH_FLAGS].Get(), f[FWD_URG_FLAGS].Get(),
                f[BWD_URG_FLAGS].Get()));

        log.info(exported.toString());
        /*for (int i = 0; i < NUM_FEATURES; i++) {
            exported.append(String.format(",%s", f[i].Export()));
        }
        exported.append(String.format(",%d", dscp));
        exported.append(String.format(",%d", firstTime));
        exported.append(String.format(",%d", flast));
        exported.append(String.format(",%d", blast));
        log.info(exported.toString());*/
        /*
        //srcIP, srcPort, dstIP, dstPort, PROTO,
        -1062726524,40416,-928054654,80,6,

        //TOTAL_FWD_PKTS, TOTAL_FVOLUME, TOTAL_BPAKCETS, TOTAL_BVOLUME,
        //FWD_PKT_LEN, BKTL, FWD_IAT, BWD_IAT, DURATION, ACTIVE, IDLE,
        //SUBFLOW_FWD_PKTS, SUBFLOW_FWD_BYTES, SUBFLOW_BWD_PKTS, SUBFLOW_BWD_BYTES,
        //FWD_PSH_FLAGS, BWD_PSH_FLAGS, FWD_URG_FLAGS, BWD_URG_FLAGS, FWD_HDR_LEN, BWD_HDR_LEN
        5,416,2,120,52,83,192,60,60,60,60,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2,208,1,60,0,0,0,0,25,10,

        //DSCP, FIRST_TIME, FLAST, BLAST
        0,1639732975,1639732975,1639732975
        */
    }

    public boolean CheckIdle(long time) {
        return (time - getLastTime()) > FLOW_TIMEOUT;
    }

    public ArrayList<Long> ToArrayList(){
        if (!valid) {
            return null;
        }
        ArrayList<Long> array = new ArrayList<Long>();

        // Sample attack flow
        // array.add(13l);
        // array.add(5220l);
        // array.add(11l);
        // array.add(1964l);
        // array.add(52l);
        // array.add(401l);
        // array.add(726l);
        // array.add(336l);
        // array.add(52l);
        // array.add(178l);
        // array.add(264l);
        // array.add(99l);
        // array.add(5l);
        // array.add(0l);
        // array.add(5l);
        // array.add(1l);
        // array.add(5l);
        // array.add(1l);
        // array.add(5l);
        // array.add(2l);
        // array.add(10l);
        // array.add(10l);
        // array.add(10l);
        // array.add(10l);
        // array.add(0l);
        // array.add(0l);
        // array.add(0l);
        // array.add(0l);
        // array.add(0l);
        // array.add(13l);
        // array.add(5220l);
        // array.add(11l);
        // array.add(1964l);
        // array.add(7l);
        // array.add(7l);
        // array.add(0l);
        // array.add(0l);
        // array.add(684l);
        // array.add(580l);

        // return array;

        // -----------------------------------
        // First, lets consider the last active time in the calculations in case
        // this changes something.
        // -----------------------------------
        long diff = getLastTime() - activeStart;
        f[ACTIVE].Add(diff);

        // ---------------------------------
        // Update Flow stats which require counters or other final calculations
        // ---------------------------------

        // More sub-flow calculations
        if (f[ACTIVE].Get() > 0) {
            f[SUBFLOW_FWD_PKTS].Set(f[TOTAL_FWD_PKTS].Get() / f[ACTIVE].Get());
            f[SUBFLOW_FWD_BYTES].Set(f[TOTAL_LEN_FWD_PKTS].Get() / f[ACTIVE].Get());
            f[SUBFLOW_BWD_PKTS].Set(f[TOTAL_BWD_PKTS].Get() / f[ACTIVE].Get());
            f[SUBFLOW_BWD_BYTES].Set(f[TOTAL_LEN_BWD_PKTS].Get() / f[ACTIVE].Get());
        }
        f[DURATION].Set(getLastTime() - firstTime);
        if (f[DURATION].Get() < 0) {
            log.error("duration ({}) < 0", f[DURATION]);
        }
        for (int i = 0; i < NUM_FEATURES; i++) {
            ArrayList<Long> featureComponents = f[i].ToArrayList();
            for (int j = 0; j < featureComponents.size(); j++){
                array.add(featureComponents.get(j));
                //Es lo mismo que array.addAll(featureComponents);
            }
        }
        return array;
    }

    private void updateTcpState(Ethernet packet) {
        IPv4 ipv4 = (IPv4) packet.getPayload();
        TCP tcp = (TCP) ipv4.getPayload();
        short flags = tcp.getFlags();
        cstate.setState(flags, P_FORWARD, pdir);
        sstate.setState(flags, P_BACKWARD, pdir);
    }

    private void updateStatus(Ethernet packet) {
        IPv4 ipv4 = (IPv4) packet.getPayload();
        long length = ipv4.getTotalLength();
        if (proto == IP_UDP) {
            if (valid) {
                return;
            }
            if (length > 8) {
                hasData = true;
            }
            if (hasData && isBidir) {
                valid = true;
            }
        } else if (proto == IP_TCP) {
            if (!valid) {
                if (cstate.getState() == TcpState.State.ESTABLISHED) {
                    if (length > ipv4.getHeaderLength()) {
                        valid = true;
                    }
                }
            }
            updateTcpState(packet);
        }
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

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof FlowData))
            return false;
        FlowData ref = (FlowData) obj;
        return this.forwardKey.equals(ref.forwardKey) && this.backwardKey.equals(ref.backwardKey);
    }
    @Override
    public int hashCode() {
        return forwardKey.hashCode() + backwardKey.hashCode();
    }

}