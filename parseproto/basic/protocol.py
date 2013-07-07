

import functools, os

# Twisted imports
from twisted.internet import error
from twisted.internet.protocol import Protocol

# Parsley imports
from ometa.protocol import ParserProtocol
from ometa.grammar import OMeta


# Parseproto
import parseproto.basic

# ParserProtocol currently only supports terml based grammar
def getGrammar(pkg, name):
    base = os.path.dirname(os.path.abspath(pkg.__file__))
    src = open(os.path.join(base, name + ".parsley")).read()
    return OMeta(src).parseGrammar(name)



class LineOnlyReceiverBaseSender(object):
    def __init__(self, transport):
        self.transport = transport

    def sendLine(self, line):
        return self.transport.writeSequence((line, '\r\n'))


class LineOnlyReceiver(Protocol):
    """
    A protocol that receives only lines.

    This is purely a speed optimisation over LineReceiver, for the
    cases that raw mode is known to be unnecessary.

    """
    MAX_LENGTH = 16384

    def updateReceiver(self, sender, parser):
        self.sender = sender
        self.parser = parser
        return self


    def connectionMade(self):
        # avoid infinite recursion
        if getattr(self, 'parserProtocol', None) is not None:
            return

        self.parserProtocol = ParserProtocol(
            getGrammar(parseproto.basic, "line_only_receiver"),
            LineOnlyReceiverBaseSender,
            self.updateReceiver,
            {}
        )
        # could be better for the next line
        self.parserProtocol.transport = self.transport
        self.parserProtocol.connectionMade()


    def dataReceived(self, data):
        return self.parserProtocol.dataReceived(data)


    def rawLineReceived(self, line):
        print("I am in and the line is:", line)
        if len(line) > self.MAX_LENGTH:
            # Invoke lineLengthExceeded
            self.lineLengthExceeded(line)
        else:
            self.lineReceived(line)

        # Explicitly set return value to be None
        # so as to keep the currentRule unchanged
        return


    def lineReceived(self, line):
        """
        Override this for when each line is received.

        @param line: The line which was received with the delimiter removed.
        @type line: C{bytes}
        """
        raise NotImplementedError


    def sendLine(self, line):
        """
        Sends a line to the other end of the connection.

        @param line: The line to send, not including the delimiter.
        @type line: C{bytes}
        """
        return self.sender.sendLine(line)


    def lineLengthExceeded(self, line):
        """
        Called when the maximum line length has been reached.
        Override if it needs to be dealt with in some special way.
        """
        return error.ConnectionLost('Line length exceeded')


    def connectionLost(self, reason):
        # a bit ugly
        self.parserProtocol.disconnecting = True