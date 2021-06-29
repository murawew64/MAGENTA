'''
Provide ECB class with ecb mode to encrypted/decrypted.
'''
from project.encryptmode import EncryptMode


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
        text = self._check_length(text)

        res = bytearray()
        for i in range(0, len(text) - 15, 16):
            res.extend(self._decode_block(text[i:i+16]))

        while res[-1] == 0:
            del res[-1]

        return res


if __name__ == "__main__":
    mg = ECB('aaaaccccbbbbddddeeeef'.encode())

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
