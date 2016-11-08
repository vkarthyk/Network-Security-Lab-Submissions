from twisted.internet import reactor, protocol
from twisted.protocols import basic

class EchoClient(protocol.Protocol):

    def connectionMade(self):
        self.transport.write("sys.argv[1]")

    def dataReceived(self, data):
        print "Received: %s" % data
        self.transport.loseConnection()

class EchoClientFactory(protocol.ClientFactory):
    protocol = EchoClient

    def clientConnectionLost(self, connector, reason):
        print "Lost connection: %s" % reason.getErrorMessage()
        reactor.stop()

    def clientConnectionFailed(self, connector, reason):
        print "Connection failed: %s" % reason.getErrorMessage()
        reactor.stop()

if __name__ == "__main__":
    import sys
    if not len(sys.argv) == 2:
        print "Usage: echoclient.py <message>"
        sys.exit(1)

    reactor.connectTCP('localhost', 9999, EchoClientFactory())
    reactor.run()
