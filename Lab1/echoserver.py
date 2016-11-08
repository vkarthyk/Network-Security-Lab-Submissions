from twisted.internet import reactor, protocol, endpoints

class Echo(protocol.Protocol):
    def dataReceived(self, data):
        self.transport.write(data)

class EchoFactory(protocol.Factory):
    protocol = Echo

endpoint = endpoints.TCP4ServerEndpoint(reactor, 9999)
endpoint.listen(EchoFactory())
reactor.run()

