#!/bin/bash

curl -sS --fail https://repo1.maven.org/maven2/org/onosproject/onos-releases/2.2.2/onos-admin-2.2.2.tar.gz \
  > tools.tar.gz
tar xf tools.tar.gz
mv onos-admin-2.2.2 tools