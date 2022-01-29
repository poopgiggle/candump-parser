import re
import struct



def hex_string_to_bytes(hex_string, width=None):
    '''
    Take candump-style hex string (hex chars smooshed together with no spaces or commas) and convert to byte string

    hex_string: the hex string to convert
    width: expected width of the byte field (in nibbles). If this isn't specified, don't pad.

    Returns byte string
    '''

    while width and len(hex_string) < width:
        hex_string = '0' + hex_string

    assert len(hex_string) % 2 == 0, "Incorrectly formatted byte string"
    assert len(hex_string) < 128, "String is way too long for CAN purposes"

    return bytearray([int(hex_string[x:x+2], 16) for x in range(0, len(hex_string), 2)])

def csv_hex_to_bytes(hex_string):
    #trim trailing comma
    try:
        if hex_string[-1] == ',':
            hex_string = hex_string[:-1]
    except IndexError:
        return b''

    str_list = hex_string.split(',')
    return bytes(list(map(lambda x: int(x, 16), str_list)))

def unpack_csv(fmt, csv_str):
    return struct.unpack(fmt, csv_hex_to_bytes(csv_str))


def prettify_bytes(byte_string):
    '''
    Take byte string and return comma-separated hex value
    '''

    byte_list = struct.unpack("B"*len(byte_string), byte_string)
    return ",".join(["{:02x}".format(x) for x in byte_list])

def hex_string(byte_string):
    '''
    Take byte string and return unseparated hex string
    '''
    if type(byte_string) is int:
        return "{:02x}".format(byte_string)
    else:
        return "".join(["{:02x}".format(x) for x in byte_string])
