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

import java.util.ArrayList;

/**
 * ValueFlowFeature
 */
public class ValueFlowFeature implements IFlowFeature {
    /**
     * Properties
     */
    public long value;

    public ValueFlowFeature(long l){
        Set(l);
    }

    @Override
    public void Add(long l) {
        value += l;
    };

    @Override
    public String Export() {
        return String.format("%d", value);
    };

    @Override
    public long Get() {
        return value;
    };

    @Override
    public void Set(long l) {
        value = l;
    };

    @Override
    public ArrayList<Long> ToArrayList() {
        ArrayList<Long> array = new ArrayList<Long>();
        array.add(value);
        return array;
    };
}