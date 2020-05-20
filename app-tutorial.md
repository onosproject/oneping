# ONOS Application Tutorial
ONOS is a distributed system designed to support distributed network control 
applications. It is authored in Java and uses OSGi to dynamically load and unload
applications, drivers and other types of extensions throughout the entire cluster.

Note that you can also create "external" applications that don't directly run
on the ONOS platform, but can interact with it using the ONOS REST API. Such
applications can be developed using a programming language of your choice.
It is also possibly to develop hybrid applications comprising an ONOS core 
extension authored in Java and an off-platform counterpart communicating with 
each other using method of their preference, e.g. REST API, gRPC, Kafka, Thrift.

This tutorial will show how to easily create, build and deploy a skeletal Java
application that can be used as a starting point for developing your own 
network control logic.

First, let's go over some prerequisites and basics.

### Download ONOS Admin Tools
ONOS comes with a set of tools for developers and for remote administration of ONOS cluster.
They are part of the ONOS source, but are also available to download as a 
separate bundle. To install a local copy of these tools run the following command:
```
$ ./get-onos-tools.sh
```
We will use these tools later.

## Basics
ONOS application subsystem is built atop the Apache Karaf feature service, 
which is in turn built using the standard OSGi bundle management services.
An ONOS app is defined in terms Karaf features and provides means to contain 
the features definitions (`features.xml`) as well as any required OSGi bundles 
into a single artifact. This artifact, an OAR file - as in ONOS Application aRchive - 
is then used to deliver the application software across the entire ONOS cluster.

## Create an App
One of the ONOS tools that we downloaded is `onos-create-app`. It can be used 
to create a skeletal application, which is ready to build and deploy.

Let's create our new application as a peer to the `oneping` application. So first,
change the working directory:
```
$ cd ..
```

And now use the `onos-create-app` to generate our application as follows:
```
$ oneping/tools/onos-create-app app org.bar foo-app 1.2 org.bar.foo
```
We've asked the tool to generate a plain `app` project, that when built, 
will assemble into and artifact with ID `foo-app`, version `1.2` and that can
be published under group with ID `org.bar`; the project Java code will be 
located under package `org.bar.foo`. 

Internally, the tool uses Maven archetypes to create different flavours of projects from a
basic app (which is what we created above) to apps with CLI, REST API and various
GUI features.

## Build the App
The newly generated app project can be built as is. Simply change your working
directory and use Maven to build the project as follows:
```
$ cd foo-app
$ mvn package
```

After the packaging completes, you should see a newly created OAR file `target/foo-app-1.2.oar`
that contains the packaged skeletal app.

### Start ONOS
Before we can deploy our application, you must have a running ONOS instance (or cluster).
For the purpose of this exercise, you can easily start a single ONOS instance 
using the officially released docker image. From a separate shell, run the following:
```
$ ../oneping/start-onos.sh
```
ONOS will run in the foreground of this shell and will print its log.

## Deploy the App
You are now ready to deploy this as an ONOS app. This can be done using the ONOS 
CLI, REST API, GUI, but for this exercise, we will use the `onos-app` tool, which
is effectively just a wrapper around the REST API.

Assuming we have an ONOS instance running on the local machine, we can install 
and immediately activate (the `!` in `install!`) our new app as follows:
```
$ oneping/tools/onos-app localhost install! target/foo-app-1.2.oar
```

You should see the ONOS logs indicate that the app has been installed and started.
Of course, since this application is merely a skeleton, it will not do anything 
useful beyond printing a start-up message. It is now up to us to code the network 
control or monitoring functionality.

For a simple example of accomplishing both using P4 and protocol-independent flow rule
programming abstraction of ONOS, see [`OnePing.java`](src/main/java/org/onos/oneping/OnePing.java).