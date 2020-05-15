# oneping
Sample ONOS 2.x application showing how to use ONOS forwarding abstractions.

## Build
Requires Java 11 and Maven to be installed in your development environment.
To compile the sources and to assemble the ONOS application archive (`.oar`) file, run the following:
```
> mvn clean install
```

## Deploy
To deploy the `oneping` application into a running ONOS 2.2.2 cluster (or single instance), you can use the
ONOS REST API, ONOS GUI. You can also use the ONOS admin tool `onos-app` as follows:

```
> onos-app <onos-ip> install! target/oneping-2.0.0.oar
```
