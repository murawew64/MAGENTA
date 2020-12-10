'''

'''
from abc import ABCMeta, abstractmethod


class Magenta:

    __metaclass__ = ABCMeta

    def __init__(self, key: bytes):
        '''
        Constructor takes key with length 16 or 24 or 32 bytes.
        '''
        self._s = self._generate_S()
        self._check_key(key)

    def _check_key(self, key: bytes):
        '''
        Check key length. If length not equals 16, 24, 32 complite.
        '''
        key_length = len(key)

        if key_length < 16:
            self._key = key + bytes(16 - key_length)

        elif key_length < 24:
            self._key = key + bytes(24 - key_length)

        elif key_length < 32:
            self._key = key + bytes(32 - key_length)

    @abstractmethod
    def encode(self, text: bytes):
        '''
        Encode text.
        '''

    @abstractmethod
    def decode(self, text: bytes):
        '''
        Decode text.
        '''

    def _encode_block_16(self, block: bytes):
        '''
        Encode block with key 16 bytes.
        '''
        k1, k2 = self._key[:8], self._key[8:]

        res = self._FK(k1, self._FK(k1, self._FK(
            k2, self._FK(k2, self._FK(k1, self._FK(k1, block))))))

        return res

    def _encode_block_24(self, block: bytes):
        '''
        Encode block with key 24 bytes.
        '''
        k1, k2, k3 = self._key[:8], self._key[8:16], self._key[16:24]

        res = self._FK(k1, self._FK(k2, self._FK(
            k3, self._FK(k3, self._FK(k2, self._FK(k1, block))))))

        return res

    def _encode_block_32(self, block: bytes):
        '''
        Encode block with key 32 bytes.
        '''
        k1, k2 = self._key[:8], self._key[8:16]
        k3, k4 = self._key[16:24], self._key[24:32]

        res = self._FK(k1, self._FK(k2, self._FK(k3, self._FK(k4, self._FK(
            k4, self._FK(k3, self._FK(k2, self._FK(k1, block))))))))

        return res

    def _encode_block(self, block: bytes):
        '''
        Takes block 16 bytes.
        Return encrypted block 16 bytes.
        '''
        key_len = len(self._key)
        if key_len == 16:
            return self._encode_block_16(block)

        elif key_len == 24:
            return self._encode_block_24(block)

        else:
            return self._encode_block_32(block)

    def _decode_block(self, block: bytes):
        '''
        Takes block 16 bytes.
        Return decrypted block 16 bytes.
        '''
        return self._V(self._encode_block(self._V(block)))

    def _FK(self, key: bytes, block: bytes):
        '''
        Раундовая функция.
        Входной блок `block` размером 128 бит раунда n c раундовым ключом `key`(64 бит) разбивается на 2 части X1 и X2 размером 64 бита каждая.
        '''
        assert len(key) == 8
        assert len(block) == 16

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
        # возвращаются первые 8 байт
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
        Takes 1 byte, return 1 byte. 
        Byte takes as int.
        Return element by index `x` in s-block.
        '''
        assert 0 <= x <= 255

        return self._s[x]

    def _A(self, x: int, y: int):
        '''
        Функция, которая принимает 1 байт и возвращает 1 байт.
        Байт принимается как число.
        '''
        assert 0 <= x <= 255
        assert 0 <= y <= 255

        return self._f(x ^ self._f(y))

    def _PE(self, x: int, y: int):
        '''
        Функция принимает на вход 1 байт и возвращает 2 байта.
        Принимается число, возвращается кортеж из двух байт.
        Конкатенирует результаты A(x, y) и A(y, x).
        '''
        assert 0 <= x <= 255
        assert 0 <= y <= 255

        return (self._A(x, y), self._A(y, x))

    def _P(self, arr_x: bytes):
        '''
        X=X0X1...X14X15
        (PE(X0,X8)PE(X1,X9)...PE(X6,X14)PE(X7,X15)) - конкатенирует результаты PE(Xi,Xi+8) i=0...7, Xi имеет размер 1 байт.
        Входной параметр - массив 16 байт, возвращает 16 байт
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
        Рекурсивная функция:
        С(1,X) = T(X)
        С(k,X) = T(X ⊕ S(C(k-1,X)))
        Принимает на вход и возвращает 16 байт
        '''
        assert k >= 1
        assert len(arr_x) == 16

        if k == 1:
            return self._T(arr_x)

        # intermediate array
        imd = self._S(self._C(k-1, arr_x))

        # побайтовый XOR массивов
        res = bytearray()
        for i in range(16):
            res.append(arr_x[i] ^ imd[i])

        return self._T(res)


if __name__ == "__main__":
    mg = Magenta('aaaaccccbbbbddddeeeeffff'.encode())

    s = 'a' * 16 + 'b' * 16 + 'c' * 16 + 'd' * 16 + 'e' * 16
    open_text = s.encode()
    print('text', open_text)

    enc = mg.encode(open_text)
    print('enc', enc)

    # mg._key = 'aaaaccccbbbbdddd'.encode()

    dec = mg.decode(enc)
    print('dec', dec)
