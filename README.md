# C/U-Plane Attacker

## Introduction

The tool is designed based on DPDK-burst-replay to conduct O-RAN.TIFG.E2E-Test.0-v03.00 Secton 7.2.2 C-Plane eCPRI DoS Attack (Network layer).

## How to play with it

### Install dependencies

* dpdk-dev (obsly)
* libnuma-dev
* That's all.

NB: libpcap is not required, as dpdk-replay process pcap files manually.

### Compiling and installing it

> RTE_SDK= <DPDK_PATH>
> export PCAP_DIR=<CUFH_ATTACKER_PATH>/Traffic
> make -f DPDK_Makefile && sudo cp build/cufh-attacker /usr/bin

### Launching it

> cufh-attacker [TRAFFIC-TYPE] [OPTIONS] PORT1[,PORTX...]

Example:
> cufh-attacker --up-ul-r 1,10,1 --numacore 0 --dst 11:22:33:44:77:11 03:00.1


## BSD LICENCE

Copyright 2018 Jonathan Ribas, FraudBuster. All rights reserved.


Modified 2023 by Ferlinda Feliana.
