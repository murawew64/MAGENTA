'''
Provide intermadiate class with common modes tools.
'''

import magenta


class EncryptMode(magenta.Magenta):

    def __init__(self, key, c0):
        #
        key = self._check_key(key)
        super().__init__(key)
        self._check_c0(c0)

    def _check_c0(self, c0):
        '''
        Check c0 length. If length < 16 complite if > 16 cut.
        '''
        if len(c0) < 16:
            self._c0 = c0 + bytes(16 - len(c0))

        elif len(c0) > 16:
            self._c0 = c0[:16]

        else:
            self._c0 = c0

    def _check_key(self, key: bytes):
        '''
        Check key length. If length not equals 16, 24, 32 complite.
        If great then 32 cut.
        '''
        key_length = len(key)

        if key_length == 16 or key_length == 24 or key_length == 32:
            return key

        if key_length < 16:
            return key + bytes(16 - key_length)

        elif key_length < 24:
            return key + bytes(24 - key_length)

        elif key_length < 32:
            return key + bytes(32 - key_length)

        else:
            return key[:32]
