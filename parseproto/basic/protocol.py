

import functools, os
from struct import pack, calcsize

# Twisted imports
from twisted.internet import error
from twisted.internet.protocol import Protocol
# expedient import for _something
from twisted.protocols.basic import _PauseableMixin, StringTooLongError

# Parsley imports
from ometa.protocol import ParserProtocol as BaseParserProtocol
from ometa.grammar import OMeta


# Parseproto
import parseproto.basic

# ParserProtocol currently only supports terml based grammar
def getGrammar(pkg, name):
    base = os.path.dirname(os.path.abspath(pkg.__file__))
    src = open(os.path.join(base, name + ".parsley")).read()
    return OMeta(src).parseGrammar(name)


class ParserProtocol(BaseParserProtocol):

    def connectionMade(self):
        self.sender = self.senderFactory(self.transport)
        self.bindings['receiver'] = self.receiver = self.receiverFactory(self.sender, self)
        self.receiver.prepareParsing()
        self._setupInterp()


    def connectionLost(self, reason):
        if self.disconnecting:
            return
        self.receiver.finishParsing(reason)
        self.disconnecting = True


class _ReceiverMixin():
    _parserProtocol = None
    _parsleyGrammar = b''
    _bindings = {}

    def _updateReceiver(self, sender, parser):
        self.sender = sender
        self.parser = parser
        return self

    def _initializeParserProtocol(self):
        self._parserProtocol = ParserProtocol(
                getGrammar(parseproto.basic, self._parsleyGrammar),
                self._senderFactory,
                self._updateReceiver,
                self._bindings
            )
        self._parserProtocol.makeConnection(self.transport)


    def prepareParsing(self):
        """
        Invoked before parsing
        """

    def finishParsing(self, reason):
        """
        Invoked before to stop parsing
        """


class LineOnlyReceiverBaseSender(object):
    def __init__(self, transport):
        self.transport = transport

    def sendLine(self, line):
        return self.transport.writeSequence((line, '\r\n'))



class LineOnlyReceiver(_ReceiverMixin, Protocol):
    """
    A protocol that receives only lines.

    This is purely a speed optimisation over LineReceiver, for the
    cases that raw mode is known to be unnecessary.

    """
    MAX_LENGTH = 16384
    _parsleyGrammar = 'line_only_receiver'
    _senderFactory = LineOnlyReceiverBaseSender

    def dataReceived(self, data):
        if self._parserProtocol is None:
            self._initializeParserProtocol()
        return self._parserProtocol.dataReceived(data)


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
        if self._parserProtocol is None:
            self._initializaParserProtocol()
        return self.sender.sendLine(line)


    def lineLengthExceeded(self, line):
        """
        Called when the maximum line length has been reached.
        Override if it needs to be dealt with in some special way.
        """
        return error.ConnectionLost('Line length exceeded')

    def connectionLost(self, reason):
        self._parserProtocol.connectionLost(reason)




class IntNStringReceiverBaseSender(object):
    def __init__(self, transport):
        self.transport = transport


    def sendString(self, string, structFormat):
        self.transport.write(pack(structFormat, len(string)) + string)



class IntNStringReceiver(Protocol, _PauseableMixin, _ReceiverMixin):
    MAX_LENGTH = 99999
    _unprocessed = b''
    _parsleyGrammar = 'intn_string_receiver'
    _senderFactory = IntNStringReceiverBaseSender

    def stringReceived(self, string):
        """
        Override this for notification when each complete string is received.

        @param string: The complete string which was received with all
            framing (length prefix, etc) removed.
        @type string: C{bytes}
        """
        raise NotImplementedError


    def lengthLimitExceeded(self, length):
        """
        Callback invoked when a length prefix greater than C{MAX_LENGTH} is
        received.  The default implementation disconnects the transport.
        Override this.

        @param length: The length prefix which was received.
        @type length: C{int}
        """

        self.transport.loseConnection()


    def dataReceived(self, data):
        """
        Convert int prefixed strings into calls to stringReceived.
        """
        if self._parserProtocol is None:
            self._initializeParserProtocol()
        self._unprocessed += data
        if self.paused:
            return
        # we should make ParserProtocol be able to pause when new data is added
        self._parserProtocol.dataReceived(self._unprocessed)
        self._unprocessed = b''


    def sendString(self, string):
        """
        Send a prefixed string to the other end of the connection.

        @param string: The string to send.  The necessary framing (length
            prefix, etc) will be added.
        @type string: C{bytes}
        """
        if len(string) >= 2 ** (8 * self.prefixLength):
            raise StringTooLongError(
                "Try to send %s bytes whereas maximum is %s" % (
                len(string), 2 ** (8 * self.prefixLength)))

        if self._parserProtocol is None:
            self._initializeParserProtocol()
        self.sender.sendString(string, self.structFormat)


    def getStringLength(self, slen):
        length = 0
        for s in slen:
            length = length << 8 | ord(s)
        return length


    def checkStringLength(self, length):
        return length < self.MAX_LENGTH


    def connectionLost(self, reason):
        self._parserProtocol.connectionLost(reason)


class Int32StringReceiver(IntNStringReceiver):
    """
    A receiver for int32-prefixed strings.

    An int32 string is a string prefixed by 4 bytes, the 32-bit length of
    the string encoded in network byte order.

    This class publishes the same interface as NetstringReceiver.
    """
    structFormat = "!I"
    prefixLength = calcsize(structFormat)



class Int16StringReceiver(IntNStringReceiver):
    """
    A receiver for int16-prefixed strings.

    An int16 string is a string prefixed by 2 bytes, the 16-bit length of
    the string encoded in network byte order.

    This class publishes the same interface as NetstringReceiver.
    """
    structFormat = "!H"
    prefixLength = calcsize(structFormat)



class Int8StringReceiver(IntNStringReceiver):
    """
    A receiver for int8-prefixed strings.

    An int8 string is a string prefixed by 1 byte, the 8-bit length of
    the string.

    This class publishes the same interface as NetstringReceiver.
    """
    structFormat = "!B"
    prefixLength = calcsize(structFormat)

