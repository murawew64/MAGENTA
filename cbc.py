'''

'''

from encryptmode import EncryptMode


class CBC(EncryptMode):

    def encode(self, text: bytes):
        '''
        Encode text.
        '''
        text = self._check_length(text)

        prev = self._c0
        res = bytearray()
        for i in range(0, len(text) - 15, 16):
            prev = self._encode_block(self._xor_bytes(text[i:i+16], prev))
            res.extend(prev)

        return res

    def decode(self, text: bytes):
        '''
        Decode text
        '''
        if len(text) % 16:
            raise Exception(
                'Error: text length not divide by 16 (block length)!')

        prev = self._c0
        res = bytearray()
        for i in range(0, len(text) - 15, 16):
            res.extend(self._xor_bytes(self._decode_block(text[i:i+16]), prev))
            prev = text[i:i+16]

        while res[-1] == 0:
            del res[-1]

        return res


if __name__ == "__main__":
    mg = CBC('aaaaccccbbbbddddeeeef'.encode(), 'aaaaccccbbbb1231'.encode())

    s = 'a' * 16 + 'b' * 16 + 'c' * 16 + 'd' * 16 + 'e' * 3
    open_text = s.encode()
    print('text', open_text)

    enc = mg.encode(open_text)
    print('enc', enc)

    # mg._key = 'aaaaccccbbbbdddd'.encode()

    dec = mg.decode(enc)
    print('dec', dec)
