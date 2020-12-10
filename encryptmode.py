'''
Provide intermadiate class with common modes tools.
'''

import magenta


class EncryptMode(magenta.Magenta):

    def __init__(self, key, c0):
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
