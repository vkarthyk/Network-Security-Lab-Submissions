from twisted.internet.protocol import Protocol, ClientFactory
from twisted.internet import reactor, defer
from twisted.internet.endpoints import TCP4ClientEndpoint, connectProtocol
from playground.twisted.endpoints import GateClientEndpoint
import sys

class HttpClient(Protocol):

    def sendMessage(self, msg):
        self.transport.write(msg)

    def dataReceived(self, data):
        print "Received: %s" % data
        self.transport.loseConnection()
        reactor.stop()

def gotProtocol(p):
    request = "GET "+ sys.argv[1] +" HTTP/1.1\r\nHost: localhost\r\n\r\n"
    reactor.callLater(0, p.sendMessage, request)

point = GateClientEndpoint.CreateFromConfig(reactor, "20164.0.0.1", 101)
d = connectProtocol(point, HttpClient())
d.addCallback(gotProtocol)
reactor.run()

