import re
import struct
from .network_messages import ISOSession, ISORequest, ISOResponse
from .utils import unpack_csv, csv_hex_to_bytes, prettify_bytes

log_line_prefix = '^FT:\d+,AT:\d+\s+'

#All log lines that we're interested in seem to start with this
#Not totally sure what the numbers are but might as well capture them
log_line = re.compile('^FT:(\d+),AT:(\d+).*')

call_line = re.compile('^FT:\d+,AT:\d+\s+\w{2},(CC|SC|RM|SM|CD)')

#groups: client_id, protocol
cc_line = re.compile(log_line_prefix+'XX,CC,\d{2},(\d{2}),\d+?,([^,]+?),.*')

#the one captured group is the client number
rm_line = re.compile('^FT:\d+,AT:\d+\s+(\d{2}),RM,.*')

#groups are: length, timestamp, echo byte, indicator status, msg type, CAN ID, extended address, data
iso_rm_line = re.compile('\d{2},RM,(\d+),\d+,\d+,((?:[a-fA-F0-9]{2},){4})([a-fA-F0-9]{2}),([a-fA-F0-9]{2}),([a-fA-F0-9]{2}),((?:[a-fA-F0-9]{2},){4})([a-fA-F0-9]{2}),(.*)')

#groups are: client id, timestamp, j1708 data
j1708_rm_line = re.compile(log_line_prefix+'(\d{2}),RM,\d{2},\d+,\d+,((?:[a-fA-F0-9]{2},){4})(.*)')

#continuation of RM data. Make sure to test that line isn't a call line
data_line = re.compile('^FT:\d+,AT:\d+\s+([a-fA-F0-9]{2},(?!CC|SC|RM|SM|CD|DV).*)')

#groups are: length, msg type, CAN ID, extended address, data
iso_sm_line = re.compile('\d{2},SM,\d+,(\d+),(?:\d+,){2}([a-fA-F0-9]{2}),((?:[a-fA-F0-9]{2},){4})([a-fA-F0-9]{2}),(.*)')

#groups are: client id, timestamp, j1708 data
j1708_sm_line = re.compile('(\d{2}),SM,\d{2},((?:[a-fA-F0-9]{1,2},){4})(.*)')

def _parse_data_line(msg_line):
    match = data_line.search(msg_line)
    if not match:
        return None

    data = match.groups()[0]
    data = csv_hex_to_bytes(data)
    return data

def _parse_j1708_helper(msg_line, j1708_client_num, regex_object):
    '''
    Helper function for _parse_j1708_{read,send}_message_line.
    Got that DRY shit on lock.
    '''
    match = regex_object.match(msg_line)
    if not match:
        return None
    try:
        (raw_client_id, raw_timestamp, raw_data) = match.groups()
        client_id = int(raw_client_id)
        if client_id != j1708_client_num:
            return None

        timestamp = unpack_csv(">L", raw_timestamp)[0]
        data = csv_hex_to_bytes(raw_data)

        return (client_id, timestamp, data)
    except ValueError:
        return None

def _parse_j1708_read_message_line(msg_line, j1708_client_num):
    return _parse_j1708_helper(msg_line, j1708_client_num, j1708_rm_line)

def _parse_j1708_send_message_line(msg_line, j1708_client_num):
    return _parse_j1708_helper(msg_line, j1708_client_num, j1708_sm_line)
    


def _parse_iso_read_message_line(msg_line):
    match = iso_rm_line.search(msg_line)
    if not match:
        return (None,) * 8

    (length, timestamp, echo, ind_status, msg_type, can_id, ext_addr, data) = match.groups()
    length = int(length)
    timestamp = unpack_csv(">L", timestamp)[0]
    echo = unpack_csv("B", echo)[0]
    ind_status = unpack_csv("B", ind_status)[0]
    msg_type = unpack_csv("B", msg_type)[0]
    can_id = unpack_csv(">L", can_id)[0]
    ext_addr = unpack_csv("B", ext_addr)[0]
    data = csv_hex_to_bytes(data)

    return (length, timestamp, echo, ind_status, msg_type, can_id, ext_addr, data)

def _parse_iso_send_message_line(msg_line):
    match = iso_sm_line.search(msg_line)
    if not match:
        return (None,) * 5

    (length, msg_type, can_id, ext_addr, data) = match.groups()
    length = int(length)
    msg_type = unpack_csv("B", msg_type)[0]
    can_id = unpack_csv(">L", can_id)[0]
    ext_addr = unpack_csv("B", ext_addr)[0]
    data = csv_hex_to_bytes(data)

    return (length, msg_type, can_id, ext_addr, data)

def load(filehandle):
    '''
    shortcut for DPAParser.load(...)
    '''
    return DPAParser().load(filehandle)

class DPAParser(object):
    '''
    Parser for DPA debug log files.

    Currently assumes that the logfile is for a ISO15765 session, called with the
    same commands that DAVIE uses. J1939, J1708, J1850, CAN, etc will break this.

    I tried to keep (mostly) the same interface betwen this and CandumpParser but there will
    be some differences b/c DPA doesn't give raw CAN traffic for ISO sessions.
    '''
    def __init__(self):
        self.log_lines = []

    def load(self, f):
        for line in f.readlines():
            if log_line.match(line):
                self.log_lines.append(line)

        return self

    def get_1708_traffic(self):
        '''
        extract J1708 traffic from DPA logfile
        '''
        j1708_client = None
        j1708_messages = []
        for log_line in self.log_lines:
            if cc_line.match(log_line):
                (client_id_raw, protocol) = cc_line.match(log_line).groups()
                client_id = int(client_id_raw)
                if protocol == "J1708":
                    j1708_client = client_id
            elif _parse_j1708_read_message_line(log_line, j1708_client) is not None:
                (client_id, timestamp, data) = _parse_j1708_read_message_line(log_line, j1708_client)
                j1708_messages.append(("RM",data,))
            elif _parse_j1708_send_message_line(log_line, j1708_client) is not None:
                (client_id, timestamp, data) = _parse_j1708_send_message_line(log_line, j1708_client)
                j1708_messages.append(("SM", data,))

        return j1708_messages

    def parse_iso_sessions(self, src_addr=0xF9):
        '''
        Extract ISO15765 requests/responses.

        Must be called after load(), otherwise there's nothing to parse!
        '''
        iso_sessions = []
        current_session = None
        current_rm_data = None
        current_rm_code = None
        current_rm_pid = None
        for l_line in self.log_lines:
            if not log_line.match(l_line):
                continue #random line we don't care about
            elif iso_sm_line.search(l_line):
                if current_session is not None:
                    this_response = ISOResponse(current_rm_code, current_rm_pid, current_rm_data)
                    current_session.iso_response_data = this_response
                    iso_sessions.append(current_session)
                (length, msg_type, can_id, ext_addr, data) = _parse_iso_send_message_line(l_line)
                if can_id & 0xFFFF0000 != 0x18DA0000:
                    current_session = None
                    continue
                code = data[0]
                pid = data[1:]
                this_request = ISORequest(code, pid)
                current_session = ISOSession(src_addr)
                current_session.iso_request = this_request
            elif iso_rm_line.search(l_line):
                if current_session is None:
                    continue#probably a response we don't care about
                (length, timestamp, echo, ind_status, msg_type, can_id, ext_addr, data) = _parse_iso_read_message_line(l_line)
                if ind_status != 0 or echo != 0:
                    continue
                assert(can_id & 0xFFFF0000 == 0x18DA0000), "RM non-ISO message, or fix the parser"
                current_rm_code = data[0]
                current_rm_pid = data[1]
                current_rm_data = data[2:]
            elif data_line.match(l_line):
                data = _parse_data_line(l_line)
                current_rm_data += data
            else:#lol don't care
                continue

        return iso_sessions


