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
from ometa.tube import TrampolinedParser

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
    currentRule = "initial"

    def _initializeParserProtocol(self):
        self._trampolinedParser = TrampolinedParser(
            grammar=getGrammar(self._parsleyGrammarPKG, self._parsleyGrammarName),
            receiver=self,
            bindings=self._bindings
        )

    # this is a utility function.
    def showArg(self, *args):
        print(args)


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
            self._initializeParserProtocol()
        return self.transport.writeSequence((line, '\r\n'))


    def lineLengthExceeded(self, line):
        """
        Called when the maximum line length has been reached.
        Override if it needs to be dealt with in some special way.
        """
        return error.ConnectionLost('Line length exceeded')


class LineReceiver(BaseReceiver, _PauseableMixin):
    """
    A protocol that receives lines and/or raw data, depending on mode.

    In line mode, each line that's received becomes a callback to
    L{lineReceived}.  In raw data mode, each chunk of raw data becomes a
    callback to L{rawDataReceived}.  The L{setLineMode} and L{setRawMode}
    methods switch between the two modes.

    This is useful for line-oriented protocols such as IRC, HTTP, POP, etc.

    @cvar delimiter: The line-ending delimiter to use. By default this is
                     C{b'\\r\\n'}.
    @cvar MAX_LENGTH: The maximum length of a line to allow (If a
                      sent line is longer than this, the connection is dropped).
                      Default is 16384.
    """
    _parsleyGrammarPKG = parseproto.basic
    _parsleyGrammarName = 'line_receiver'
    _buffer = b''
    _busyReceiving = False
    delimiter = b'\r\n'
    MAX_LENGTH = 16384

    _mode = 1
    # make sure object is in this class's mro
    @property
    def line_mode(self):
        return self._mode

    @line_mode.setter
    def line_mode(self, val):
        self._mode = val
        if self._trampolinedParser is not None:
            self.currentRule = "line" if self._mode else "data"

    @line_mode.deleter
    def line_mode(self):
        del self._mode


    def clearLineBuffer(self):
        """
        Clear buffered data.

        @return: All of the cleared buffered data.
        @rtype: C{bytes}
        """
        b, self._buffer = self._buffer, b""
        return b


    def dataReceived(self, data):
        """
        Translates bytes into lines, and calls lineReceived (or
        rawDataReceived, depending on mode.)
        """
        if self._busyReceiving:
            self._buffer += data
            return

        try:
            self._busyReceiving = True
            self._buffer += data
            if not self.paused:
                if self._trampolinedParser is None:
                    self._initializeParserProtocol()
                buf, self._buffer = self._buffer, b''
                return self._trampolinedParser.receive(buf)
            # while self._buffer and not self.paused:
            #     if self.line_mode:
            #         try:
            #             line, self._buffer = self._buffer.split(
            #                 self.delimiter, 1)
            #         except ValueError:
            #             if len(self._buffer) > self.MAX_LENGTH:
            #                 line, self._buffer = self._buffer, b''
            #                 return self.lineLengthExceeded(line)
            #             return
            #         else:
            #             lineLength = len(line)
            #             if lineLength > self.MAX_LENGTH:
            #                 exceeded = line + self._buffer
            #                 self._buffer = b''
            #                 return self.lineLengthExceeded(exceeded)
            #             why = self.lineReceived(line)
            #             if (why or self.transport and
            #                 self.transport.disconnecting):
            #                 return why
            #     else:
            #         data = self._buffer
            #         self._buffer = b''
            #         why = self.rawDataReceived(data)
            #         if why:
            #             return why
        finally:
            self._busyReceiving = False


    def setLineMode(self, extra=b''):
        """
        Sets the line-mode of this receiver.

        If you are calling this from a rawDataReceived callback,
        you can pass in extra unhandled data, and that data will
        be parsed for lines.  Further data received will be sent
        to lineReceived rather than rawDataReceived.

        Do not pass extra data if calling this function from
        within a lineReceived callback.
        """
        self.line_mode = 1
        if extra:
            return self.dataReceived(extra)


    def setRawMode(self):
        """
        Sets the raw mode of this receiver.
        Further data received will be sent to rawDataReceived rather
        than lineReceived.
        """
        self.line_mode = 0


    def rawDataReceived(self, data):
        """
        Override this for when raw data is received.
        """
        raise NotImplementedError


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
        return self.transport.write(line + self.delimiter)


    def lineLengthExceeded(self, line):
        """
        Called when the maximum line length has been reached.
        Override if it needs to be dealt with in some special way.

        The argument 'line' contains the remainder of the buffer, starting
        with (at least some part) of the line which is too long. This may
        be more than one line, or may be only the initial portion of the
        line.
        """
        return self.transport.loseConnection()


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

