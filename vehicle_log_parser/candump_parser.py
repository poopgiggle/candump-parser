import re
import struct
from .network_messages import CANMessage, ISOMessage, ISOSession

def load(filehandle):
    '''
    shortcut for CandumpParser.load(...)
    '''

    return CandumpParser().load(filehandle)




class CandumpParser(object):

    def __init__(self):
        self.messages = []
        

    def load(self, f):
        '''
        Load a candump file from a file handle and parse the contents

        f: file handle
        '''
        for line in f.readlines():
            message = CANMessage().parse_candump_log_line(line)
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

