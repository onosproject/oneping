# OnePing
Sample ONOS 2.x application showing how to use ONOS forwarding abstractions.

## Build
Requires Java 11 and Maven to be installed in your development environment.
To compile the sources and to assemble the ONOS application archive (`.oar`) file, run the following:
```
$ mvn clean install
```

## Deploy
To deploy the `oneping` application into a running ONOS 2.2.2 instance, you can use the
ONOS REST API, ONOS GUI. If you already have a running ONOS instance or cluster, you
can skip down to the [Installing App](#Installing App) section.

### Download ONOS Admin Tools
ONOS comes with a set of tools for remote administration. These are primarily just wrappers
that use ONOS REST API, and make remote administration easier.

To download and unpack a local copy of these tools run the following command:
```
$ ./get-onos-tools.sh
```

### Start ONOS
You can start ONOS using the officially released docker image using the following:
```
$ ./start-onos.sh
```
ONOS will run in the foreground of this shell and will print its log.

### Installing App
The remote administraton tools include `onos-app` facility to easily manage ONOS apps
from the command line. You can use it to install our OnePing application as follows:
```
$ tools/onos-app localhost install! target/oneping-2.0.0.oar
```

## See It Work
To see the OnePing application work, you can use the Mininet. For this demonstration
as simple topology comprising of a single Stratum switch and a couple of hosts will suffice.
You can start it as follows:
```
$ ./start-mn.sh
```
This command will run in the foreground and will leave you with a `mininet>` prompt
via which you can interact with the mininet environment.

Now that mininet is running, from yet another shell, let's inform ONOS about our
switch. This can be done by uploading a simple JSON configuration file that tells ONOS
about the switch management address, and which switch driver and which pipeline driver
to use.
```
$ tools/onos-netcfg localhost netcfg.json
```
Once uploaded, ONOS will discover the switch and will start to manage it. You can use
ONOS CLI, REST API or GUI to view this simple topology.