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

/**
 * TcpState
 */
public class TcpState {
    public enum State {
        START,
        SYN,
        SYNACK,
        ESTABLISHED,
        FIN,
        CLOSED;
    }

    static final long TCP_FIN = 0x01;
    static final long TCP_SYN = 0x02;
    static final long TCP_RST = 0x04;
    static final long TCP_PUSH = 0x08;
    static final long TCP_ACK = 0x10;
    static final long TCP_URG = 0x20;
    static final long TCP_CWE = 0x80;
    static final long TCP_ECE = 0x40;

    private State state;

    public TcpState(State state) {
        this.state = state;
    }

    public State getState(){
        return state;
    }

    public void setState(short flags, int dir, short pdir){
        if (tcpSet(TCP_RST, flags)) {
            state = State.CLOSED;
        } else if (tcpSet(TCP_FIN, flags) && (dir == pdir)) {
            state = State.FIN;
        } else if (state == State.FIN) {
            if (tcpSet(TCP_ACK, flags) && (dir != pdir)) {
                state = State.CLOSED;
            }
        } else if (state == State.START) {
            if (tcpSet(TCP_SYN, flags) && (dir == pdir)) {
                state = State.SYN;
            }
        } else if (state == State.SYN) {
            if (tcpSet(TCP_SYN, flags) && tcpSet(TCP_ACK, flags) && (dir != pdir)) {
                state = State.SYNACK;
            }
        } else if (state == State.SYNACK) {
            if (tcpSet(TCP_ACK, flags) && (dir == pdir)) {
                state = State.ESTABLISHED;
            }
        }
    }

    static boolean tcpSet(long find, short flags) {
        return ((find & flags) == find);
    }
}