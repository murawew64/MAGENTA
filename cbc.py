'''
Provide CBC class with cbc mode to encrypted/decrypted.
'''

from project.encryptmode import EncryptMode


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
        text = self._check_length(text)

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

    with open('File/1.jpg', 'rb') as f:
        open_text = f.read()

    enc = mg.encode(open_text)
    with open('File/2.jpg', 'wb') as f:
        f.write(enc)

    with open('File/2.jpg', 'rb') as f:
        close_text = f.read()

    dec = mg.decode(close_text)
    with open('File/3.jpg', 'wb') as f:
        f.write(dec)
