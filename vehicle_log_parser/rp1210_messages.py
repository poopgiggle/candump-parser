import re
import struct

class RP1210LogLine(object):
    fmt = '^FT:(\d+),AT:(\d+)'
    allowed = ('FT', 'AT')
    def __init__(self, *args, **kwargs):
        for k,v in kwargs.items():
            assert( k in self.__class__.allowed )
            setattr(self, k, v)

    def from_log_line(self, log_line):




