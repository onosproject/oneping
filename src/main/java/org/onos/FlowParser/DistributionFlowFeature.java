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
import org.onos.Helpers;

/**
 * DistributionFlowFeature
 */
public class DistributionFlowFeature implements IFlowFeature {
    /**
     * Properties
     */
    public long sum;
    public long sumsq;
    public long count;
    public long min;
    public long max;

    public DistributionFlowFeature(long l){
        Set(l);
    }

    @Override
    public void Add(long l) {
        sum += l;
        sumsq += l * l;
        count++;
        if ((l < min) || (min == 0)) {
            min = l;
        }
        if (l > max) {
            max = l;
        }
    };

    @Override
    public String Export() {
        long stdDev = 0;
        long mean = 0;
        if (count > 0) {
            stdDev = (long) Helpers.stddev((float) sumsq, (float) sum, count);
            mean = sum / count;
        }
        return String.format("%d,%d,%d,%d", min, mean, max, stdDev);
    };

    @Override
    public long Get() {
        return count;
    };

    @Override
    public void Set(long l) {
        sum = l;
        sumsq = l * l;
        count = l;
        min = l;
        max = l;
    };

    @Override
    public ArrayList<Long> ToArrayList() {
        ArrayList<Long> array = new ArrayList<Long>();
        long stdDev = 0;
        long mean = 0;
        if (count > 0) {
            stdDev = (long) Helpers.stddev((float) sumsq, (float) sum, count);
            mean = sum / count;
        }
        array.add(min);
        array.add(mean);
        array.add(max);
        array.add(stdDev);
        return array;
    };

    public String ToString() {
        return Export();
    }
}