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
 * BinFlowFeature, which takes values and bins them according to their value.
 */
public class BinFlowFeature implements IFlowFeature {
    /**
     * Properties
     */
    public int numBins; // The number of bins for this feature
    public int binSep; // Ie. the magnitude of the range contained in each bin
    public int[] bins; // Stores the actual count for each bin

    /**
     * Initializes the BinFeature to contain bins starting at min and going to max.
     * Anything below min is thrown into the lowest bin, and anything above max is
     * put in the last bin. numBins is the number of bins required in the range
     * [min, max]
     */
    public BinFlowFeature(int min, int max, int numBins) {
        this.numBins = numBins;
        int diff = max - min;
        binSep = diff / numBins;
        bins = new int[numBins];
        for (int i = 0; i < numBins; i++) {
            bins[i] = 0;
        }
    }

    @Override
    public void Add(long l) {
        int bin = Helpers.min((int) l / binSep, numBins);
        bins[bin] += 1;
    };

    @Override
    public String Export() {
        String ret = "";
        for (int i = 0; i < bins.length; i++) {
            if (i > 0) {
                ret += ",";
            }
            ret += String.format("%d", bins[i]);
        }
        return ret;
    };

    @Override
    public long Get() {
        return (long) bins[0];
    };

    @Override
    public void Set(long l) {
        for (int i = 0; i < bins.length; i++) {
            bins[i] = (int) l;
        }
    }

    @Override
    public ArrayList<Long> ToArrayList() {
        ArrayList<Long> array = new ArrayList<Long>();
        for (int i = 0; i < bins.length; i++) {
            array.add((long) bins[i]);
        }
        return array;
    };
}