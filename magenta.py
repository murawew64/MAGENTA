'''
Provide Magenta class to encode and decode data.
'''


class Magenta():

    def __init__(self, key: bytes):
        '''
        Constructor takes key with length 16 or 24 or 32 bytes.
        '''
        self._s = self._generate_S()
        self._key = key
        self._get_key_order(key)

    def _get_key_order(self, key: bytes):
        '''
        Takes key 16 or 24 or 32 bytes.
        Return key order array for encryption.
        '''
        key_len = len(key)
        if key_len == 16:
            k1, k2 = self._key[:8], self._key[8:]
            self._key_order = (k1, k1, k2, k2, k1, k1)

        elif key_len == 24:
            k1, k2, k3 = key[:8], key[8:16], key[16:24]
            self._key_order = (k1, k2, k3, k3, k2, k1)

        else:  # key_len == 32
            k1, k2 = key[:8], key[8:16]
            k3, k4 = key[16:24], key[24:32]
            self._key_order = (k1, k2, k3, k4, k4, k3, k2, k1)

    def _encode_block(self, block: bytes):
        '''
        Takes block 16 bytes.
        Return encrypted block 16 bytes.
        '''
        imd = block
        for k in self._key_order:
            imd = self._FK(k, imd)

        return imd

    def _decode_block(self, block: bytes):
        '''
        Takes block 16 bytes.
        Return decrypted block 16 bytes.
        '''
        return self._V(self._encode_block(self._V(block)))

    def _FK(self, key: bytes, block: bytes):
        '''
        Round function.
        Takes `block` 16 bytes and round `key` 8 bytes.
        '''
        assert len(key) == 8 and len(block) == 16

        # split block 16 bytes into two blocks 8 bytes
        x1, x2 = block[:8], block[8:]

        # (X(2),X(1) xor F(X(2),SK(n)))
        imd = self._F(x2 + key)
        r = bytearray()
        for i in range(8):
            r.append(imd[i] ^ x1[i])

        return x2 + r

    def _F(self, block: bytes):
        '''
        Takes 16 bytes, return first 8 bytes of _S(_C(3, block))
        '''
        assert len(block) == 16
        res = self._S(self._C(3, block))

        return res[:8]

    @staticmethod
    def _V(arr: bytes):
        '''
        Permute arr
        '''
        assert len(arr) == 16

        return arr[8:] + arr[:8]

    @staticmethod
    def _generate_S():
        '''
        Generate s-block.
        '''
        el = 1
        s_arr = [1]
        for _ in range(255):
            el <<= 1
            if el > 255:
                el = (0xFF & el) ^ 101
            s_arr.append(el)
        s_arr[255] = 0

        return s_arr

    def _f(self, x: int):
        '''
        Takes 1 byte, return 1 byte. Byte takes as int.
        Return element by index `x` in s-block.
        '''
        assert 0 <= x <= 255

        return self._s[x]

    def _A(self, x: int, y: int):
        '''
        Takes and return 1 byte.
        Byte takes as int.
        '''
        assert 0 <= x <= 255 and 0 <= y <= 255

        return self._f(x ^ self._f(y))

    def _PE(self, x: int, y: int):
        '''
        Takes `x`, `y`: 1 byte, return tuple with 2 bytes.
        Concat results of A(x, y) and A(y, x).
        '''
        assert 0 <= x <= 255 and 0 <= y <= 255

        return (self._A(x, y), self._A(y, x))

    def _P(self, arr_x: bytes):
        '''
        Takes and return 16 bytes.
        X=X0X1...X14X15
        (PE(X0,X8)PE(X1,X9)...PE(X6,X14)PE(X7,X15)) - concat results PE(Xi,Xi+8) i=0...7, Xi - 1 byte.
        '''
        assert len(arr_x) == 16

        res = bytearray()
        for i in range(8):
            res.extend(self._PE(arr_x[i], arr_x[i+8]))

        return res

    def _T(self, arr_x: bytes):
        '''
        Use _P(arr_x) function 4 time.
        '''
        assert len(arr_x) == 16

        res = arr_x
        for _ in range(4):
            res = self._P(res)

        return res

    @staticmethod
    def _S(arr_x: bytes):
        '''
        Permute bytes `arr_x`: first write bytes with even sequence number, then other.
        '''
        assert len(arr_x) == 16

        permut = [0, 2, 4, 6, 8, 10, 12, 14, 1, 3, 5, 7, 9, 11, 13, 15]
        res = bytearray()
        for index in permut:
            res.append(arr_x[index])

        return res

    def _C(self, k: int, arr_x: bytes):
        '''
        Recursive function:
        С(1,X) = T(X)
        С(k,X) = T(X ^ S(C(k-1,X)))
        Takes and return 16 bytes.
        '''
        assert k >= 1 and len(arr_x) == 16

        if k == 1:
            return self._T(arr_x)

        # intermediate array
        imd = self._S(self._C(k-1, arr_x))

        res = self._xor_bytes(arr_x, imd)

        return self._T(res)

    @staticmethod
    def _xor_bytes(b1: bytes, b2: bytes):
        '''
        Return b1 ^ b2
        '''
        assert len(b1) == 16 and len(b2) == 16

        res = bytearray()
        for i in range(16):
            res.append(b1[i] ^ b2[i])

        return res


if __name__ == "__main__":
    mgnt = Magenta('keykeykeykeykeyk'.encode())
    close_text = mgnt._encode_block('messagemessageme'.encode())
    open_text = mgnt._decode_block(close_text)
    print(open_text)
