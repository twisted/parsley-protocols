import functools, os
from struct import pack, calcsize

# Twisted imports
from twisted.internet import error, protocol
# expedient import for _something
from twisted.protocols.basic import _PauseableMixin, StringTooLongError
# from twisted.protocols.basic import _RecvdCompatHack

# Parsley imports
from ometa.grammar import OMeta


# Parseproto
import parseproto.basic
from parseproto.util.tube import TrampolinedParser

# ParserProtocol currently only supports terml based grammar
def getGrammar(pkg, name):
    base = os.path.dirname(os.path.abspath(pkg.__file__))
    src = open(os.path.join(base, name + ".parsley")).read()
    return OMeta(src).parseGrammar(name)


class _ReceiverMixin(object):
    _trampolinedParser = None
    _parsleyGrammarName = b''
    _parsleyGrammarPKG = None
    _bindings = {}

    def _initializeParserProtocol(self):
        self._trampolinedParser = TrampolinedParser(
            grammar=getGrammar(self._parsleyGrammarPKG, self._parsleyGrammarName),
            receiver=self,
            bindings=self._bindings
        )


class BaseReceiver(_ReceiverMixin, protocol.Protocol):
    """
    This class act as the base receiver for stream oriented protocol.
    """


class LineOnlyReceiver(BaseReceiver):
    """
    A protocol that receives only lines.

    This is purely a speed optimisation over LineReceiver, for the
    cases that raw mode is known to be unnecessary.

    """
    MAX_LENGTH = 16384
    _parsleyGrammarPKG = parseproto.basic
    _parsleyGrammarName = 'line_only_receiver'

    def dataReceived(self, data):
        if self._trampolinedParser is None:
            self._initializeParserProtocol()
        return self._trampolinedParser.receive(data)


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
        if self._trampolinedParser is None:
            self._initializaParserProtocol()
        return self.transport.writeSequence((line, '\r\n'))


    def lineLengthExceeded(self, line):
        """
        Called when the maximum line length has been reached.
        Override if it needs to be dealt with in some special way.
        """
        return error.ConnectionLost('Line length exceeded')



# class _RecvdCompatHack(object):
#     def __get__(self, oself, type=None):
#         return oself._unprocessed[:]


class IntNStringReceiver(BaseReceiver, _PauseableMixin):
    MAX_LENGTH = 99999
    _unprocessed = b''
    _parsleyGrammarPKG = parseproto.basic
    _parsleyGrammarName = 'intn_string_receiver'
    # recvd = _RecvdCompatHack()

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
        if self._trampolinedParser is None:
            self._initializeParserProtocol()
        self._unprocessed += data
        if self.paused:
            return
        #if 'recvd' in self.__dict__:
        #    alldata = self.__dict__.pop('recvd')
        #    print("if I were ever in")
        #    # self._unprocessed += alldata
        # need a second thought here.
        # self._compatibilityOffset = len(self._unprocessed)
        # self._unprocessed, unprocessed = b'', self._unprocessed
        self._trampolinedParser.receive(self._unprocessed)
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
        return self.transport.write(pack(self.structFormat, len(string)) + string)


    def getStringLength(self, slen):
        length = 0
        for s in slen:
            length = length << 8 | ord(s)
        return length


    def checkStringLength(self, length):
        return length < self.MAX_LENGTH



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

