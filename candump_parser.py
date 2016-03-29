import re
import struct

_msg_pattern = re.compile('\(([0-9\.]+)\) (can\d) ([A-F0-9]+)\#([A-F0-9]+)')

def hex_string_to_bytes(hex_string, width=None):
    '''
    Take candump-style hex string (hex chars smooshed together with no spaces or commas) and convert to byte string

    hex_string: the hex string to convert
    width: expected width of the byte field (in nibbles). If this isn't specified, don't pad.

    Returns byte string
    '''

    assert len(hex_string) % 2 ==0, "Incorrectly formatted byte string"
    assert len(hex_string) < 128, "String is way too long for CAN purposes"

    return bytes([int(hex_string[x:x+2], 16) for x in range(0, len(hex_string), 2)])

def prettify_bytes(byte_string):
    '''
    Take byte string and return comma-separated hex value
    '''

    byte_list = struct.unpack("B"*len(byte_string), byte_string)
    return ",".join(["{:02x}".format(x) for x in byte_list])

def load(filehandle):
    '''
    shortcut for CandumpParser.load(...)
    '''

    return CandumpParser().load(filehandle)

def _parse_log_line(logline):
    (timestamp, interface, raw_can_id, raw_can_data) = _msg_pattern.match(logline).groups()
    can_id = struct.unpack('>L', hex_string_to_bytes(raw_can_id))[0]#This may break on 11-bit IDs
    can_data = hex_string_to_bytes(raw_can_data)

    return (timestamp, interface, can_id, can_data)

def _format_can_id(can_id):
    return "{:08x}".format(can_id)


class CANMessage(object):

    def __init__(self, timestamp=None, interface=None, can_id=None, can_data=None):
        if timestamp:
            self.timestamp = timestamp
        if interface:
            self.interface = interface
        if can_id:
            self.can_id = can_id
        if can_data:
            self.can_data = can_data


    def parse_log_line(self, logline):
        (self.timestamp, self.interface, self.can_id, self.can_data) = _parse_log_line(logline)
        return self

    def __repr__(self):
        if self.can_id:
            disp_can_id = _format_can_id(self.can_id)
        else:
            disp_can_id = None
        if self.can_data:
            disp_can_data = prettify_bytes(self.can_data)
        else:
            disp_can_data = None
        return "<{} {} {} {}>".format(self.timestamp, self.interface, disp_can_id, disp_can_data)

class ISOMessage(CANMessage):

    def from_can(self, canmessage):
        '''
        Copies the data from a CANMessage instance into the ISOMessage instance
        '''

        assert canmessage.can_id & 0xFFFF0000 == 0x18DA0000, "Tried to cast a non-ISO message as ISO"

        self.timestamp = canmessage.timestamp
        self.interface = canmessage.interface
        self.can_id = canmessage.can_id
        self.can_data = canmessage.can_data

        return self

    def parse_iso(self):
        assert self.can_id & 0xFFFF0000 == 0x18DA0000, "Not an ISO message"

        self.src = self.can_id & 0x000000FF
        self.dst = self.can_id & 0x0000FF00

        return self

    @property
    def is_transport(self):
        return self.can_data[0] & 0xF0 != 0

    @property
    def is_first_message(self):
        return (self.can_data[0] & 0xF0) >> 4 == 1

    @property
    def is_later_message(self):
        return (self.can_data[0] & 0xF0) >> 4 == 2

    @property
    def is_flow_control_message(self):
        return (self.can_data[0] & 0xF0) >> 4 == 3


class ISOSession(object):
    def __init__(self, src, dst=0):#assume dst is ECM address
        self.src = src
        self.dst = dst
        self.messages = []

    def add(self, iso_msg):
        self.messages.append(iso_msg)
        return self

    @property
    def response_messages(self):
        return filter(lambda x: x.src == self.dst, self.messages)


    @property
    def session_data_length(self):
        length_responses = list(filter(lambda x: not x.is_transport or x.is_first_message, self.response_messages))
        assert len(length_responses) == 1, "More than one response initiation in session, probably parse error"

        resp = length_responses[0]
        if resp.is_first_message:
            upper_byte = (resp.can_data[0] & 0x0F) << 8
            lower_byte = resp.can_data[1]
            return upper_byte | lower_byte
        else:
            return resp.can_data[0]

    @property
    def response_data(self):
        data = []
        for msg in self.response_messages:
            if msg.is_first_message:
                data.append(msg.can_data[2:])
            elif msg.is_later_message or not msg.is_transport:
                data.append(msg.can_data[1:])
            elif msg.is_flow_control_message:
                raise Exception("Flow control message shouldn't be categorized in responses")
            elif not msg.is_transport:
                data.append(msg.can_data)

        return b','.join(data)[:self.session_data_length]

    



class CandumpParser(object):

    def __init__(self):
        self.messages = []
        

    def load(self, f):
        '''
        Load a candump file from a file handle and parse the contents

        f: file handle
        '''
        for line in f.readlines():
            message = CANMessage().parse_log_line(line)
            self.messages.append(message)

        return self

    @property
    def iso_messages(self):
        return [ISOMessage().from_can(x).parse_iso() for x in filter(lambda x: x.can_id and x.can_id & 0xFFFF0000 == 0x18DA0000, self.messages)]

    def parse_iso_sessions(self, src_addr=0xF9):
        '''
        Extract ISO15765 requests/responses.

        src_addr: the source address making the request. 0xf9 by default.

        Returns list of ISOSession objects
        '''
        sessions = []
        iso_messages = self.iso_messages

        #find first ISO message from src
        first_sent = None
        for i, msg in enumerate(iso_messages):
            if msg.src ==src_addr:
                first_sent = i
                break

        if first_sent is None:
            return

        this_session = ISOSession(src_addr).add(iso_messages[first_sent])
        
        for msg in iso_messages[first_sent+1:]:
            if msg.src == src_addr and not msg.is_flow_control_message:
                sessions.append(this_session)
                this_session = ISOSession(src_addr).add(msg)
            else:
                this_session.add(msg)

        return sessions

