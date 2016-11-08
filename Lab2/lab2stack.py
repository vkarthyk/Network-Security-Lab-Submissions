from twisted.internet import reactor, task
from twisted.internet.protocol import Protocol, Factory
from playground.network.message.ProtoBuilder import MessageDefinition
from playground.network.message.StandardMessageSpecifiers import *
from playground.network.common.Protocol import StackingTransport, StackingProtocolMixin, StackingFactoryMixin, MessageStorage
from random import randint
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Hash import HMAC, SHA256
from playground.crypto import X509Certificate
from playground.network.common.statemachine import StateMachine as FSM
import CertFactory
import os

class RipMessage(MessageDefinition):

    PLAYGROUND_IDENTIFIER = "RipStack.RipMessage"

    MESSAGE_VERSION = "1.0"

    BODY = [("sequence_number", UINT4),
         ("acknowledgement_number", UINT4, OPTIONAL),
         ("signature", STRING, DEFAULT_VALUE("")),
         ("certificate", LIST(STRING), OPTIONAL),
         ("sessionID", STRING, OPTIONAL),
         ("acknowledgement_flag", BOOL1, DEFAULT_VALUE(False)),
         ("close_flag", BOOL1, DEFAULT_VALUE(False)),
         ("sequence_number_notification_flag", BOOL1, DEFAULT_VALUE(False)),
         ("reset_flag", BOOL1, DEFAULT_VALUE(False)),
         ("data", STRING, DEFAULT_VALUE("")),
         ("OPTIONS", LIST(STRING), OPTIONAL)
    ]


    # Transmission Control Block to store the parameters
class TransmissionControlBlock():
    def __init__(self):
        self.sequence_number = randint(1, 1000)
        self.next_seq_expected = 0
        self.nonce = os.urandom(8).encode('hex')
        self.peer_nonce = 0
        self.peerCert = ""
        self.peerCaCert = ""
        self.retransmissionBuffer = {}
        self.receivedMessages = {}
        self.max_segment_size = 4096
        self.timer = {}

class RipTransport(StackingTransport):
    def __init__(self, lowerTransport, protocol, TCB):
        StackingTransport.__init__(self, lowerTransport)
        self.TCB = protocol.TCB
        self.protocol = protocol

    def write(self, data):
        message_index = 0

        # Segment the data based on the maximum segment size
        segmentList = [data[i:i + self.TCB.max_segment_size] for i in range(0, len(data), self.TCB.max_segment_size)]

        for msg in segmentList:
            message = RipMessage()
            message.data = msg
            message_index += self.TCB.max_segment_size
            message.sessionID = str(self.TCB.nonce) + str(self.TCB.peer_nonce)
            message.sequence_number = self.TCB.sequence_number
            message.max_segment_size = self.TCB.max_segment_size
            message.signature = self.signMessage(message)

            self.lowerTransport().write(message.__serialize__())
            self.TCB.retransmissionBuffer[message.sequence_number] = message
            self.TCB.sequence_number += len(message.data)

        task.deferLater(reactor, 4, self.protocol.retransmitPackets)
            #print "%s: Message sent with Seq No. %s" % (self.protocol.factory.State, message.sequence_number)

    def loseConnection(self):
        packet = RipMessage()
        packet.sequence_number = self.TCB.sequence_number
        packet.close_flag = True
        self.lowerTransport().write(packet.__serialize__())
        self.protocol.fsm.signal("CLOSE_Requested", packet)
        print "%s: CLOSE Sent with Sequence Number %s" % (self.protocol.factory.State, packet.sequence_number)

    def signMessage(self, message):
        rawKey = CertFactory.getPrivateKeyForAddr(str(self.getHost()).split(':')[0])
        rsaKey = RSA.importKey(rawKey)
        rsaSigner = PKCS1_v1_5.new(rsaKey)
        hm = SHA256.new()
        hm.update(message.__serialize__())
        signedMessage = rsaSigner.sign(hm)
        return signedMessage


class RipProtocol(StackingProtocolMixin, Protocol):
    def __init__(self):

        self.buffer = ""
        self.storage = MessageStorage()
        self.TCB = TransmissionControlBlock()
        self.higherTransport = RipTransport(self.transport, self, self.TCB)
        self.fsm = FSM("RipStateMachine")
        self.fsm.addState("Closed", ("Send_SNN", "SNN-SENT"))
        self.fsm.addState("Listening", ("SNN_Received", "ACK-Sent"))
        self.fsm.addState("SNN-SENT", ("SNN_ACK_Received", "Established"), onEnter=self.sendSyn)
        self.fsm.addState("ACK-Sent", ("ACK_Received", "Established"), onEnter=self.sendSynAck)
        self.fsm.addState("Established", ("CLOSE_Requested", "CLOSE-REQ"), ("CLOSE_Received", "CLOSE-RECV"), onEnter = self.sendAck)
        self.fsm.addState("CLOSE-REQ", ("CLOSE_ACK_Received", "Closed"))
        self.fsm.addState("CLOSE-RECV", ("CLOSE_ACK_Sent", "Listening"), onEnter=self.sendFinAck)


    def connectionMade(self):
        self.higherTransport = RipTransport(self.transport, self, self.TCB)
        if self.factory.State == "CLIENT": self.fsm.start("Closed")
        elif self.factory.State =="SERVER": self.fsm.start("Listening")

        if (self.factory.State == "CLIENT" and self.fsm.currentState() == "Closed"):
            self.fsm.signal("Send_SNN", '')

    def dataReceived(self, data):

        self.buffer += data
        self.storage.update(data)

        for msg in self.storage.iterateMessages():
            try:
                message = msg
            except Exception, e:
                print "Error", e
                return

            # If SNN is received
            if (message.sequence_number_notification_flag and self.fsm.currentState() == "Listening"):
                    print "%s SNN Received with Sequence No %s" % (self.factory.State, message.sequence_number)
                    self.fsm.signal("SNN_Received", message)

            # If SNN-ACK in received
            elif (message.sequence_number_notification_flag and message.acknowledgement_flag
                  and message.acknowledgement_number == self.TCB.sequence_number and self.fsm.currentState() == "SNN-SENT"):
                    print "%s: SNN-ACK Received with Sequence No %s" % (self.factory.State, message.sequence_number)
                    self.fsm.signal("SNN_ACK_Received", message)
                    self.makeHigherConnection(self.higherTransport)

            # If final ACK is received
            elif (not message.sequence_number_notification_flag and message.acknowledgement_flag and
                          message.acknowledgement_number == self.TCB.sequence_number and self.fsm.currentState() == "ACK-Sent"):
                if self.checkMessageIntegrity(message):
                    peerCert = message.certificate
                    signedNonce = peerCert[0]
                    cert = self.TCB.peerCert
                    caCert = self.TCB.peerCaCert

                    if (self.verifySignedNonce(cert, caCert, signedNonce)):
                        self.fsm.signal("ACK_Received", message)
                        print "%s: ACK Received with Sequence No %s" % (self.factory.State, message.sequence_number)
                        self.TCB.next_seq_expected = message.sequence_number + 1
                        self.makeHigherConnection(self.higherTransport)

            # If a message is received by one of the users
            elif (message.data != "" and self.fsm.currentState() == "Established"
                  and message.sessionID == str(self.TCB.peer_nonce) + str(self.TCB.nonce)
                  and not message.acknowledgement_flag and not message.close_flag
                  and message.sequence_number == self.TCB.next_seq_expected ):
                if self.checkMessageIntegrity(message):
                    self.TCB.next_seq_expected = message.sequence_number + len(str(message.data))
                    # Add the message to the list of received messages
                    self.TCB.receivedMessages[message.sequence_number] = message
                    self.sendMessageAck(message.data)

            # If ACK for the packet is received
            elif (self.fsm.currentState() == "Established" and message.sessionID == str(self.TCB.peer_nonce) + str(self.TCB.nonce)
                  and message.acknowledgement_flag and not message.close_flag):
                # Remove the acknowledged message from the retransmission buffer
                for key, message in list(self.TCB.retransmissionBuffer.items()):
                    if key <= message.acknowledgement_number:
                        del self.TCB.retransmissionBuffer[key]

            # If CLOSING ACK is received
            elif (message.close_flag and message.acknowledgement_number and self.fsm.currentState() == "CLOSE-REQ"):
                print "%s: CLOSE ACK Received with Sequence Number %s" % (self.factory.State, message.sequence_number)
                if self.TCB.retransmissionBuffer:
                    self.retransmitPackets()
                self.fsm.signal("CLOSE_ACK_Received", message)
                self.closeConnection()

            elif (message.sequence_number_notification_flag and self.fsm.currentState() == "Established"):
                self.closeConnection()

    # HANDLERS
    def sendSyn(self, signal, message):
        certChain = CertFactory.getCertsForAddr(str(self.transport.getHost()).split(':')[0])
        certBytes = certChain[0]
        caCertBytes = certChain[1]

        packet = RipMessage()
        packet.sequence_number_notification_flag = True
        packet.sequence_number = self.TCB.sequence_number
        packet.data = ""
        packet.certificate = [self.TCB.nonce, certBytes, caCertBytes]
        packet.signature = self.signMessage(packet)

        self.TCB.sequence_number = self.TCB.sequence_number + 1
        self.transport.write(packet.__serialize__())
        print "%s: SNN Sent with Sequence Number %s" % (self.factory.State, packet.sequence_number)


    def sendSynAck(self, signal, message):
        cert = message.certificate[1]
        caCert = message.certificate[2]
        self.TCB.peerCert = cert
        self.TCB.peerCaCert = caCert

        if(self.verifyCertChain(cert, caCert, message)):
            self.TCB.peer_nonce = message.certificate[0]
            self.TCB.peer_nonce = self.intToNonce(int(self.TCB.peer_nonce, 16) + 1)
            self.TCB.next_seq_expected = message.sequence_number + 1
            signedNonce = self.updateAndSignNonce(self.TCB.peer_nonce)

            certChain = CertFactory.getCertsForAddr(str(self.transport.getHost()).split(':')[0])
            certBytes = certChain[0]
            caCertBytes = certChain[1]

            ack_packet = RipMessage()
            ack_packet.certificate = [self.TCB.nonce, signedNonce, certBytes, caCertBytes]
            ack_packet.sequence_number_notification_flag = True
            ack_packet.acknowledgement_flag = True
            ack_packet.sequence_number = self.TCB.sequence_number
            ack_packet.acknowledgement_number = self.TCB.next_seq_expected
            ack_packet.data = ""
            ack_packet.signature = self.signMessage(message)

            self.TCB.sequence_number += 1
            self.transport.write(ack_packet.__serialize__())
            print "%s: SNN_ACK Sent with Sequence Number %s and Ack No %s" \
                  % (self.factory.State, ack_packet.sequence_number, ack_packet.acknowledgement_number)


    def sendAck(self, signal, message):
        if signal == "SNN_ACK_Received":
            # Verify that the issuer of the certificate is indeed the CA and
            # check if this subject name matches the source playground address of the packet
            signedNonce = message.certificate[1]
            cert = message.certificate[2]
            caCert = message.certificate[3]
            nonce = message.certificate[0]

            self.TCB.peerCert = cert
            self.TCB.peerCaCert = caCert

            if (self.verifyCertChain(cert, caCert, message) and self.validateSign(cert, caCert)
                and self.verifySignedNonce(cert, caCert, signedNonce)):

                peer_nonce = int(nonce, 16)
                peer_nonce += 1
                self.TCB.peer_nonce = self.intToNonce(peer_nonce)

                self.TCB.next_seq_expected = message.sequence_number + 1
                signatureBytes = self.updateAndSignNonce(self.TCB.peer_nonce)

                packet = RipMessage()
                packet.certificate = [signatureBytes]
                packet.data = ""
                packet.acknowledgement_flag = True
                packet.sequence_number = self.TCB.sequence_number
                packet.acknowledgement_number = self.TCB.next_seq_expected
                packet.signature = self.signMessage(packet)

                self.TCB.sequence_number += 1
                self.transport.write(packet.__serialize__())
                print "%s ACK Sent with Sequence Number %s and Ack No %s" \
                      % (self.factory.State, packet.sequence_number, packet.acknowledgement_number)

    def sendFinAck(self, signal, message):
        if (signal == "CLOSE_Received"):
            packet = RipMessage()
            packet.acknowledgement_flag = True
            packet.sequence_number = self.TCB.sequence_number + 1
            packet.close_flag = True
            packet.signature = self.signMessage(packet)
            self.transport.write(packet.__serialize__())
            print "%s: CLOSE ACK Sent with Sequence Number %s" % (self.factory.State, packet.sequence_number)
            self.fsm.signal("CLOSE_ACK_Sent", message)

    def sendMessageAck(self, data):
        message = RipMessage()
        message.sequence_number = self.TCB.sequence_number
        message.acknowledgement_number = self.TCB.next_seq_expected
        message.acknowledgement_flag = True
        message.sessionID = str(self.TCB.nonce) + str(self.TCB.peer_nonce)
        message.signature = self.signMessage(message)
        self.transport.write(message.__serialize__())
        self.higherProtocol().dataReceived(data)

    def verifyCertChain(self, cert, caCert, message):
        peerCert = X509Certificate.loadPEM(cert)
        peerCaCert = X509Certificate.loadPEM(caCert)
        rootCert = X509Certificate.loadPEM(CertFactory.getRootCert())

        # Verify that the issuer of the certificate is indeed the CA and
        # and the issuer of the peer certificate is the Internediate CA
        if (peerCaCert.getIssuer() == rootCert.getSubject() and peerCert.getIssuer() == peerCaCert.getSubject()
            and peerCert.getSubject()['commonName'] == str(self.transport.getPeer()).split(':')[0]):
            return True

    def checkMessageIntegrity(self, message):
        cert = self.TCB.peerCert
        peerCert = X509Certificate.loadPEM(cert)
        peerPublicKeyBlob = peerCert.getPublicKeyBlob()
        peerPublicKey = RSA.importKey(peerPublicKeyBlob)
        rsaVerifier = PKCS1_v1_5.new(peerPublicKey)
        signedMessage = str(message.signature)
        message.signature = ""
        messageHasher = SHA256.new()
        messageHasher.update(message.__serialize__())
        if rsaVerifier.verify(messageHasher, signedMessage):
            return True


    def validateSign(self, cert, caCert):
        peerCert = X509Certificate.loadPEM(cert)
        peerCaCert = X509Certificate.loadPEM(caCert)
        caPkBytes = peerCaCert.getPublicKeyBlob()
        caPublicKey = RSA.importKey(caPkBytes)
        caVerifier = PKCS1_v1_5.new(caPublicKey)
        hasher = SHA256.new()
        bytesToVerify = peerCert.getPemEncodedCertWithoutSignatureBlob()
        hasher.update(bytesToVerify)

        if caVerifier.verify(hasher, peerCert.getSignatureBlob()):
            return True


    def updateAndSignNonce(self, peer_nonce):
        rawKey = CertFactory.getPrivateKeyForAddr(str(self.transport.getHost()).split(':')[0])
        rsaKey = RSA.importKey(rawKey)
        rsaSigner = PKCS1_v1_5.new(rsaKey)
        hm = SHA256.new()
        hm.update(peer_nonce)
        signatureBytes = rsaSigner.sign(hm)
        return signatureBytes


    def verifySignedNonce(self, cert, caCert, signedNonce):
        peerCert = X509Certificate.loadPEM(self.TCB.peerCert)
        peerCaCert = X509Certificate.loadPEM(caCert)
        peerPublicKeyBlob = peerCert.getPublicKeyBlob()
        peerPublicKey = RSA.importKey(peerPublicKeyBlob)
        rsaVerifier = PKCS1_v1_5.new(peerPublicKey)
        caPkBytes = peerCaCert.getPublicKeyBlob()
        caPublicKey = RSA.importKey(caPkBytes)
        caVerifier = PKCS1_v1_5.new(caPublicKey)
        hasher = SHA256.new()
        bytesToVerify = peerCert.getPemEncodedCertWithoutSignatureBlob()
        hasher.update(bytesToVerify)

        if caVerifier.verify(hasher, peerCert.getSignatureBlob()):
            nonce = int(self.TCB.nonce, 16)
            nonce = nonce + 1
            self.TCB.nonce = self.intToNonce(nonce)
            hasher2 = SHA256.new()
            hasher2.update(self.TCB.nonce)
            # Check if the hash of (nonce + 1) matches the decrypted nonce received
            if (rsaVerifier.verify(hasher2, signedNonce)):
                return True

    def intToNonce(self, i):
        h = hex(i)
        h = h[2:]  # remove 0x
        if h[-1] == 'L':
            h = h[:-1]  # remove "L"
        return h

    def signMessage(self, message):
        rawKey = CertFactory.getPrivateKeyForAddr(str(self.transport.getHost()).split(':')[0])
        rsaKey = RSA.importKey(rawKey)
        rsaSigner = PKCS1_v1_5.new(rsaKey)
        hm = SHA256.new()
        hm.update(message.__serialize__())
        signedMessage = rsaSigner.sign(hm)
        return signedMessage

    def retransmitPackets(self):
        if self.TCB.retransmissionBuffer:
            counter = 0
            for seq_no, message in list(self.TCB.retransmissionBuffer.items()):
                if counter == 10:
                    return
                counter += 1
                self.transport.write(message.__serialize__())


                #print "%s: Message retransmitted with Seq No. %s" % (self.factory.State, message.sequence_number)

    def closeConnection(self):
        self.higherProtocol().connectionLost(self.higherTransport)


class ConnectingFactory(StackingFactoryMixin, Factory):
    State = "CLIENT"
    protocol = RipProtocol

class ListeningFactory(StackingFactoryMixin, Factory):
    State = "SERVER"
    protocol = RipProtocol

ConnectFactory = ConnectingFactory
ListenFactory = ListeningFactory
