'''

'''
from encryptmode import EncryptMode
from magenta import Magenta


class ECB(EncryptMode):

    def __init__(self, key):
        super().__init__(key, bytes())

    def encode(self, text: bytes):
        '''
        Encode text.
        '''
        text = self._check_length(text)
        res = bytearray()
        for i in range(0, len(text) - 15, 16):
            res.extend(self._encode_block(text[i:i+16]))

        return res

    def decode(self, text: bytes):
        '''
        Decode text
        '''
        if len(text) % 16:
            raise Exception(
                'Error: text length not divide by 16 (block length)!')
        res = bytearray()
        for i in range(0, len(text) - 15, 16):
            res.extend(self._decode_block(text[i:i+16]))

        while res[-1] == 0:
            del res[-1]

        return res


if __name__ == "__main__":
    mg = ECB('aaaaccccbbbbddddeeeef'.encode())

    s = 'a' * 16 + 'b' * 16 + 'c' * 16 + 'd' * 16 + 'e' * 3
    open_text = s.encode()
    print('text', open_text)

    enc = mg.encode(open_text)
    print('enc', enc)

    # mg._key = 'aaaaccccbbbbdddd'.encode()

    dec = mg.decode(enc)
    print('dec', dec)
