# OnePing
Sample ONOS 2.x application showing how to use ONOS protocol-independent 
flow rule programming abstractions.

## Build
Requires Java 11 and Maven to be installed in your development environment.
To compile the sources and to assemble the ONOS application archive (`.oar`) file, run the following:
```
$ mvn clean install
```

## Demo Environment
To test the application, you will need to run ONOS 2.2.2 and a Mininet network,
 or equivalently a network with Stratum switch configured with `basic.p4` pipeline.

### Start ONOS
You can start ONOS using the officially released docker image using the following:
```
$ ./start-onos.sh
```
ONOS will run in the foreground of this shell and will print its log.

### Download ONOS Admin Tools
ONOS comes with a set of tools for remote administration. These are primarily just wrappers
that use ONOS REST API, and make remote administration easier. We will use them in later steps.

To download and unpack a local copy of these tools run the following command:
```
$ ./get-onos-tools.sh
```

## Start Mininet
For this demonstration, a simple topology comprising a single Stratum switch,
and a couple of hosts will suffice. You can start it as follows:
```
$ ./start-mn.sh
```
This command will run in the foreground and will leave you with a `mininet>` prompt
via which you can interact with the mininet environment.

### Configure ONOS
Now that mininet is running, from yet another shell, let's inform ONOS about our
switch. This can be done by uploading a simple JSON configuration file that tells ONOS
about the switch management address, and which switch driver and which pipeline driver
to use.
```
$ tools/onos-netcfg localhost netcfg.json
```
Once uploaded, ONOS will discover the switch and will start to manage it. You can use
ONOS CLI, REST API or GUI to view this simple topology.

## See It Work
With the above ONOS and network environment ready, we can now install our application and test it.

To deploy the `oneping` application into a running ONOS 2.2.2 instance, you can use the
ONOS REST API, ONOS GUI. For brevity, we will use the `onos-app` tool to do so:
```
$ tools/onos-app localhost install! target/oneping-2.0.0.oar
```

After the application is installed, let's see if we can issue a single ping from `h1` to `h2`.
From the Mininet shell, run the following:
```
mininet> h1 ping -c 1 h2
```

You will see that the ping succeeded and in the ONOS logs, you should see messages similar to these:
```
23:13:12.847 INFO  [OnePing] Thank you, Vasili. One ping from F2:D2:F9:F8:78:00 to 52:82:FA:98:CF:2F received by device:s1
23:13:12.857 INFO  [OnePing] Thank you, Vasili. One ping from 52:82:FA:98:CF:2F to F2:D2:F9:F8:78:00 received by device:s1
``` 

This shows that our application detected the single ping between `h1` and `h2`.
If we were to repeat the above ping command, you will see that the ping will hang and eventually fail
and in the ONOS logs you will see message like this:
```
23:13:14.665 WARN  [OnePing] What are you doing, Vasili?! I said one ping only!!! Ping from F2:D2:F9:F8:78:00 to 52:82:FA:98:CF:2F has already been received by device:s1; 60 second ban has been issued
```
After 60 seconds, the application will lift the ping ban. When this happens, 
you will see the following message in the ONOS logs:
```
23:14:14.667 WARN  [OnePing] Careful next time, Vasili! Re-enabled ping from F2:D2:F9:F8:78:00 to 52:82:FA:98:CF:2F on device:s1
```

## Creating your own app
To learn how to easily create your own ONOS application, please follow this short [ONOS application tutorial](app-tutorial.md).
 