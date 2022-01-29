from .utils import hex_string, prettify_bytes, hex_string_to_bytes
import re
import struct

_msg_pattern = re.compile('\(([0-9\.]+)\) (can\d) ([A-F0-9]+)\#([A-F0-9]+)')

def _parse_single_iso_response(msg, req_code, req_pid):
    rsp_len = msg[0]
    if rsp_len < len(req_pid) + 1:
        raise NAKException

    data_len = rsp_len - 1 - len(req_pid)
    rsp_code = msg[1]
    rsp_pid = msg[2:2+len(req_pid)]
    rsp_data = msg[2+len(req_pid):2+len(req_pid)+data_len]

    return (rsp_code, rsp_pid, rsp_data)


def _format_can_id(can_id, extended):
    if extended:
        return "{:08x}".format(can_id)
    else:
        return "{:03x}".format(can_id)

def _parse_candump_log_line(logline):
    (timestamp, interface, raw_can_id, raw_can_data) = _msg_pattern.match(logline).groups()
    extended = len(raw_can_id) >= 8
    can_id = struct.unpack('>L', hex_string_to_bytes(raw_can_id,8))[0]
    can_data = hex_string_to_bytes(raw_can_data)

    return (timestamp, interface, can_id, can_data, extended)

def _parse_iso_transport_response(data, req_pid):
    #assuming that if we get a message long enough to require transport layer
    #that it's not an error response
    #Also assuming that we've already trimmed the assembled data to length

    rsp_code = data[0]
    rsp_pid = data[1]
    rsp_data = data[2:]

    return (rsp_code, rsp_pid, rsp_data)

def _parse_iso_request(msg):
    req_len = msg.can_data[0]#Length byte for ISO request
    req_code = msg.can_data[1]#Request code (i.e. ReadDataByID)
    req_pid = msg.can_data[2:2+req_len-1]

    return (req_len, req_code, req_pid)

class CANMessage(object):

    def __init__(self, timestamp=None, interface=None, can_id=None, can_data=None, extended=True):
        if timestamp:
            self.timestamp = timestamp
        if interface:
            self.interface = interface
        if can_id:
            self.can_id = can_id
        if can_data:
            self.can_data = can_data
        if extended:
            self.extended = extended


    def parse_candump_log_line(self, logline):
        (self.timestamp, self.interface, self.can_id, self.can_data, self.extended) = _parse_candump_log_line(logline)
        return self

    def __repr__(self):
        if self.can_id:
            disp_can_id = _format_can_id(self.can_id,self.extended)
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

class NAKException(Exception):
    def __str__(self):
        "Found a NAK response in log"



class ISORequest(object):#probably want to subclass ISOMessage eventually
    def __init__(self, code, pid):
        self.code = code
        self.pid = pid

    def __repr__(self):
        return "<{:02x} {}>".format(self.code, hex_string(self.pid))

class ISOResponse(ISORequest):
    def __init__(self, code, pid, data):
        super(ISOResponse, self).__init__(code, pid)
        self.data = data

    def __repr__(self):
        return "<{:02x} {} {}>".format(self.code, hex_string(self.pid), hex_string(self.data))



class ISOSession(object):
    def __init__(self, src, dst=0):#assume dst is ECM address
        self.src = src
        self.dst = dst
        self.messages = []
        self.iso_request = None
        self.iso_response_data = None

    def add(self, iso_msg):
        self.messages.append(iso_msg)
        return self

    @property
    def response_messages(self):
        return filter(lambda x: x.src == self.dst, self.messages)

    @property
    def request_message(self):
        request_list = list(filter(lambda x: x.src == self.src and not x.is_flow_control_message, self.messages))
        assert len(request_list) == 1, "Session has %d requests, probably parse error" % len(request_list)

        return request_list[0]

    @property
    def parsed_request_message(self):
        '''
        Parses request message into request length, request code, and PID (or ID) requested

        Returns tuple (req_len, req_code, req_pid)
        '''
        if self.iso_request:
            return self.iso_request

        req = self.request_message
        req_len = req.can_data[0]#Length byte for ISO request
        req_code = req.can_data[1]#Request code (i.e. ReadDataByID)
        req_pid = req.can_data[2:2+req_len]

        return ISORequest(req_code, req_pid)

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
    def request_response(self):
        return (self.parsed_request_message, self.response_data)

    @property
    def response_data(self):
        if self.iso_response_data:
            return self.iso_response_data
        request = self.parsed_request_message
        (req_code, req_pid) = (request.code, request.pid)
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

        data = b''.join(data)

        if data[0] & 0xF0 == 0:#This response didn't use transport layer
            (rsp_code, rsp_pid, rsp_data) = _parse_single_iso_response(data, req_code, req_pid)
        else:
            data = data[:self.session_data_length]
            (rsp_code, rsp_pid, rsp_data) = _parse_iso_transport_response(data, req_pid)

        return ISOResponse(rsp_code, rsp_pid, rsp_data)


    


