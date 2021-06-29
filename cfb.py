'''
Provide CFB class with cfb mode to encrypted/decrypted.
'''

from project.encryptmode import EncryptMode


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
