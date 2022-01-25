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
 * Defines the minimum set of functions needed for a FlowFeature.
 */
public interface IFlowFeature {
    /**
     * Add a particular value to a feature
     *
     * @param l the long int to be added to the feature
     */
    void Add(long l);

    /**
     * Export the contents of a feature in string form
     *
     * @return comma separeted string of the feature values
     */
    String Export();

    /**
     * Export the contents of a feature in an array form
     *
     * @return array list containing the components values
     */
    ArrayList<Long> ToArrayList();

    /**
     * Gets the first bin element
     *
     * @return long the first bin element
     */
    long Get();

    /**
     * Reset the feature to a particular value
     *
     * @param l the long int to set to the feature
     */
    void Set(long l);

}