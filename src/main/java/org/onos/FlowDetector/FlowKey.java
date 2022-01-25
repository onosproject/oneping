package org.onos.FlowDetector;
import org.onlab.packet.IPv4;

public class FlowKey {
    public Integer srcIP;
    public Integer srcPort;
    public Integer dstIP;
    public Integer dstPort;
    public Byte proto;

    public FlowKey(Integer srcIP, Integer srcPort, Integer dstIP, Integer dstPort, Byte proto) {
        this.srcIP = srcIP;
        this.srcPort = srcPort;
        this.dstIP = dstIP;
        this.dstPort = dstPort;
        this.proto = proto;
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof FlowKey))
            return false;
        FlowKey ref = (FlowKey) obj;
        return this.srcIP.equals(ref.srcIP) &&
                this.srcPort.equals(ref.srcPort) &&
                this.dstIP.equals(ref.dstIP) &&
                this.dstPort.equals(ref.dstPort) &&
                this.proto.equals(ref.proto);
    }

    public Long toLong() {
        return ((long) srcIP << 32) + ((long) srcPort << 16) + dstIP + dstPort + ((long) proto << 8);
    }

    public String toString() {
        return  IPv4.fromIPv4Address(srcIP) + "-" + IPv4.fromIPv4Address(dstIP) + "-" + srcPort + "-" + dstPort + "-" + proto;
    }

    @Override
    public int hashCode() {
        return srcIP.hashCode() ^ srcPort.hashCode() ^ dstIP.hashCode() ^ dstPort.hashCode() ^ proto.hashCode();
    }
}