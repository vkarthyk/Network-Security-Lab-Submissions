from twisted.internet.protocol import Protocol, Factory
from twisted.internet.endpoints import TCP4ServerEndpoint
from twisted.internet import reactor
from playground.twisted.endpoints import GateServerEndpoint
import os

class HttpResponse(Protocol):

    def dataReceived(self, request):
        parsedRequest = request.split("\r\n")
        parsedFirstLine = parsedRequest[0].split(" ")

        os.chdir("files/")

        if parsedFirstLine[0] == "GET":
            if parsedFirstLine[2] == "HTTP/1.0" or parsedFirstLine[2] == "HTTP/1.1":
                fname = parsedFirstLine[1]
                if os.path.isfile(fname):
                    with open(fname, 'r') as fin:
                        self.transport.write("%s 200 OK\r\n Content-Type: text/plain\r\n Content-length: %i\r\n\r\n%s" % (
                            parsedFirstLine[2], len(request), fin.read()))
                else:
                    with open("404.html", 'r') as fin:
                        self.transport.write("%s 404 Not Found\r\n Content-Type: text/plain\r\n Content-length: %i\r\n\r\n%s" % (
                            parsedFirstLine[2], len(request), fin.read()))

            else:
                with open("BadRequest.html", 'r') as fin:
                    self.transport.write("%s 400 Bad Request\r\n Content-Type: text/plain\r\n Content-length: %i\r\n\r\n%s" % (
                        parsedFirstLine[2], len(request), fin.read()))

        else:
            with open("BadRequest.html", 'r') as fin:
                self.transport.write("%s 400 Bad Request\r\n Content-Type: text/plain\r\n Content-length: %i\r\n\r\n%s" % (
                    parsedFirstLine[2], len(request), fin.read()))

        os.chdir('..')
        self.transport.loseConnection()

class HttpFactory(Factory):
    protocol = HttpResponse

endpoint = GateServerEndpoint.CreateFromConfig(reactor, 101)
endpoint.listen(HttpFactory())
reactor.run()

