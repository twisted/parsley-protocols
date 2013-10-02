import cProfile
from parseproto.test.test_basic import LineReceiver, proto_helpers


def test_maximumLineLength():
    """
    C{LineReceiver} disconnects the transport if it receives a line longer
    than its C{MAX_LENGTH}.
    """
    proto = LineReceiver()
    transport = proto_helpers.StringTransport()
    proto.makeConnection(transport)
    proto.dataReceived(b'x' * (proto.MAX_LENGTH + 1) + b'\r\nr')



if __name__ == '__main__':
    cProfile.run('test_maximumLineLength()', 'gogo')
