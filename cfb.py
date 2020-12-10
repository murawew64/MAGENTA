'''

'''

from encryptmode import EncryptMode


class CFB(EncryptMode):

    def encode(self, text: bytes):
        '''
        Encode text.
        '''
        text = self._check_length(text)

        res = bytearray()
        prev = self._c0
        for i in range(0, len(text) - 15, 16):
            prev = self._xor_bytes(self._encode_block(prev), text[i:i+16])
            res.extend(prev)

        return res

    def decode(self, text: bytes):
        '''
        Decode text
        '''
        res = bytearray()
        prev = self._c0
        for i in range(0, len(text) - 15, 16):
            res.extend(self._xor_bytes(self._encode_block(prev), text[i:i+16]))
            prev = text[i:i+16]

        while res[-1] == 0:
            del res[-1]

        return res


if __name__ == "__main__":
    mg = CFB('aaaaccccbbbbddddeeeef'.encode(), 'aaaaccccbbbb1231'.encode())

    s = 'a' * 16 + 'b' * 16 + 'c' * 16 + 'd' * 16 + 'e' * 3
    open_text = s.encode()
    print('text', open_text)

    enc = mg.encode(open_text)
    print('enc', enc)

    # mg._key = 'aaaaccccbbbbdddd'.encode()

    dec = mg.decode(enc)
    print('dec', dec)
