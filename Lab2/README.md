# Lab 2 Stack
## Overview
**lab2stack.py** - Lab 2 stack that implements the Reliable Interaction Protocol (RIP) based on the Playground RFC.The file does not take in any parameters. It just acts as the transport layer between the higher protocol and the Gate-to-Gate Protocol on the Playground Framework.

- The maximum segment size is currently set to 4096. It can be changed to either 2048 or 8192. It is set in the TransmissionControlBlock class.
- The retransmission period is currently 4 secs. That is after 4 secs the stack checks the retramsission buffer and sends any packets still left in it.
- The initial sequence numbers are selected randomly from 1 to 1000
- The nonce is declared using os.urandom(8)

**CertFactory.py** - This file returns the public, private and root certificates based on the Playground address that is passed to these methods.

