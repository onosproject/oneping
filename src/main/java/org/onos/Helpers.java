package org.onos;

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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.InputStream;
import java.lang.Math;
import java.util.ArrayList;
import java.util.HashMap;

/**
 * Helpers functions for the HTTP DDos Detector
 */
public class Helpers {

    /**
     * Calculates the standard deviation of a feature.
     * @param sqsum the square sum of the values
     * @param sum the sum of the values
     * @param count the count of the values
     * @return the standar deviation
     */
    public static float stddev(float sqsum, float sum, long count) {
        if (count < 2) {
            return 0;
        }
        float n = (float) count;
        return (float) Math.sqrt((sqsum - (sum * sum / n)) / (n - 1));
    }

    /**
     * Returns the minimum of two longs
     * @param i1
     * @param i2
     * @return the minimum from i1 and i2
     */
    public static long min(long i1, long i2) {
        if (i1 < i2) {
            return i1;
        }
        return i2;
    }

    /**
     * Returns the mininmum of two ints
     * @param i1
     * @param i2
     * @return the minimum from i1 and i2
     */
    public static int min(int i1, int i2) {
        if (i1 < i2) {
            return i1;
        }
        return i2;
    }

    /**
     * Get the mode of an array
     *
     * @param a the array containing integers
     * @return int the value that appears most often in the array
     */
    public static int mode(ArrayList<Integer> a){
        HashMap<Integer, Integer> counts = new HashMap<Integer, Integer>();
        int maxCount = 0;
        int maxN = -1;
        for(int i = 0; i < a.size(); i++){
            Integer n = a.get(i);
            int count = counts.getOrDefault(n, 0)+1;
            counts.put(n, count);
            if(count > maxCount){
                maxCount = count;
                maxN = n;
            }
        }
        return maxN;
    }

    /**
     * Get JSON object from file
     *
     * @param filepath target file path
     * @return ObjectNode from file
     */
    public static ObjectNode readJsonFile(String filepath) {
        ObjectNode json = null;
        try (InputStream stream = Helpers.class.getResourceAsStream(filepath))
        {
            //Read JSON file
            ObjectMapper mapper = new ObjectMapper();
            json = (ObjectNode) mapper.readTree(stream);

        } catch (Exception e){
            e.printStackTrace();
        }
        return json;
    }

}