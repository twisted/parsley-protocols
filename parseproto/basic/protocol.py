import functools, os
from struct import pack, calcsize

# Twisted imports
from twisted.internet import error, protocol
# expedient import for _something
from twisted.protocols.basic import _PauseableMixin, StringTooLongError
from twisted.python.failure import Failure

# Parsley imports
from ometa.grammar import OMeta
from ometa.interp import TrampolinedGrammarInterpreter, _feed_me


# Parseproto
import parseproto.basic

# ParserProtocol currently only supports terml based grammar
def getGrammar(pkg, name):
    base = os.path.dirname(os.path.abspath(pkg.__file__))
    src = open(os.path.join(base, name + ".parsley")).read()
    return OMeta(src).parseGrammar(name)


class TramplinedParser:
    currentRule = 'initial'

    def __init__(self, grammar, receiver, bindings):
        self.grammar = grammar
        self.bindings = dict(bindings)
        self.bindings['receiver'] = self.receiver = receiver
        self.prepareParsing()

    def setNextRule(self, rule):
        self.currentRule = rule

    def prepareParsing(self):
        self.receiver.prepareParsing()
        self._setupInterp()

    def _setupInterp(self):
        self._interp = TrampolinedGrammarInterpreter(
            self.grammar, self.currentRule, callback=self._parsedRule,
            globals=self.bindings)

    def _parsedRule(self, nextRule, position):
        if nextRule is not None:
            self.currentRule = nextRule

    def dataReceived(self, data):
        while data:
            try:
                status = self._interp.receive(data)
            except Exception as e:
                # maybe we should raise it?
                raise e
            else:
                if status is _feed_me:
                    return
            data = ''.join(self._interp.input.data[self._interp.input.position:])
            self._setupInterp()

    def finishParsing(self, reason):
        self.receiver.finishParsing(reason)



class _ReceiverMixin():
    _tramplinedParser = None
    _parsleyGrammar = b''
    _bindings = {}

    def _initializeParserProtocol(self):
        self._tramplinedParser = TramplinedParser(
                grammar = getGrammar(parseproto.basic, self._parsleyGrammar),
                receiver = self,
                bindings = self._bindings
            )

    def prepareParsing(self):
        """
        Invoked before parsing
        """

    def finishParsing(self, reason):
        """
        Invoked before to stop parsing
        """


class LineOnlyReceiver(_ReceiverMixin, protocol.Protocol):
    """
    A protocol that receives only lines.

    This is purely a speed optimisation over LineReceiver, for the
    cases that raw mode is known to be unnecessary.

    """
    MAX_LENGTH = 16384
    _parsleyGrammar = 'line_only_receiver'

    def dataReceived(self, data):
        if self._tramplinedParser is None:
            self._initializeParserProtocol()
        return self._tramplinedParser.dataReceived(data)


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
        if self._tramplinedParser is None:
            self._initializaParserProtocol()
        return self.transport.writeSequence((line, '\r\n'))


    def lineLengthExceeded(self, line):
        """
        Called when the maximum line length has been reached.
        Override if it needs to be dealt with in some special way.
        """
        return error.ConnectionLost('Line length exceeded')

    def connectionLost(self, reason):
        self._tramplinedParser.finishParsing(reason)


class IntNStringReceiver(protocol.Protocol, _PauseableMixin, _ReceiverMixin):
    MAX_LENGTH = 99999
    _unprocessed = b''
    _parsleyGrammar = 'intn_string_receiver'


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
        if self._tramplinedParser is None:
            self._initializeParserProtocol()
        self._unprocessed += data
        if self.paused:
            return
        # we should make ParserProtocol be able to pause when new data is added
        self._tramplinedParser.dataReceived(self._unprocessed)
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


    def connectionLost(self, reason):
        self._tramplinedParser.finishParsing(reason)


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

