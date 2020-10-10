import struct
import binascii


#
# This might be helpful for some when dealing w/ strings and bytes.
#

def s2b(s: str) -> bytes:
    """ Converts an ASCII string to binary."""
    return bytes(list(map(ord, s)))

def b2s(b: bytes) -> str:
    """ Converts bytes to a (best-effort) ASCII string."""
    return "".join(map(chr, b))


class Sha1:
    """ Implements the SHA1 hash function: https://tools.ietf.org/html/rfc3174.

    Emulates a barebones version of the hashlib.hash interface. See
    https://docs.python.org/3/library/hashlib.html#hashlib.hash.digest_size
    for details on the available methods and attributes.

    We only provide some of them:
        - update(data): adds bytes data to the hash
        - digest(): returns the hash value for the data added thus far
        - hexdigest(): like digest, but returns a hex string

    We ALSO provide some extra parameters to the *digest() methods to make a
    length extension attack easier. However, you will still need to read the
    relevant sections of the RFC to understand how to use them.
    """
    name = "sha1"
    digest_size = 20
    block_size = 512 / 8


    def __init__(self):
        self._buffer = b""

    def update(self, data):
        if isinstance(data, str):
            try:
                # try to be helpful and assume strings are ascii
                data = s2b(data)
            except:
                print("Please only pass ASCII strings or binary data to update().")
                raise

        assert isinstance(data, bytes), "data must be encoded as bytes"
        self._buffer += data

    def digest(self, extra_length=0, initial_state=None):
        return binascii.a2b_hex(self.hexdigest())

    def hexdigest(self, extra_length=0, initial_state=None):
        tag = self.sha1(self._buffer, extra_length=extra_length, initial_state=initial_state)
        self._buffer = b""
        return tag

    def clear(self):
        self._buffer = b""

    #
    # You may (probably do) want to access the SHA1 methods directly to craft
    # your exploit.
    #
    @staticmethod
    def create_padding(message, extra_length=0):
        """ Creates message padding as described in
        https://tools.ietf.org/html/rfc3174#section-4

        Includes the `extra_length` parameter for... convenience purposes.
        """
        l = len(message) * 8 + extra_length
        l2 = ((l // 512) + 1) * 512
        padding_length = l2 - l
        if padding_length < 72:
            padding_length += 512
        assert padding_length >= 72, "padding too short"
        assert padding_length % 8 == 0, "padding not multiple of 8"

        # Encode the length and add it to the end of the message.
        zero_bytes = (padding_length - 72) // 8
        length = struct.pack(">Q", l)
        pad = bytes([0x80] + [0] * zero_bytes)

        return pad + length

    @staticmethod
    def pad_message(message, extra_length=0):
        """ Actually pads the message.
        https://tools.ietf.org/html/rfc3174#section-4
        """
        if not isinstance(message, bytes):
            raise ValueError("message should be binary data (bytes)")

        pad = Sha1.create_padding(message, extra_length)
        message = message + pad
        assert (len(message) * 8) % 512 == 0, "message not multiple of 512"
        return message

    @staticmethod
    def sha1(message, extra_length=0, initial_state=None):
        """ Returns the 20-byte hex digest of the message.

        It's possible to override some of the SHA1 algorithm's internals using
        the keyword parameters.

        https://tools.ietf.org/html/rfc3174#section-6.1
        """
        H = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
        if initial_state is not None:
            if len(initial_state) != 5 or \
               any([not isinstance(x, int) for x in initial_state]):
                raise ValueError("initial_state should be a list of 5 integers")
            H = initial_state

        # pad according to the RFC (and then some)
        padded_msg = Sha1.pad_message(message, extra_length=extra_length)

        # break message into chunks
        M = [padded_msg[i:i+64] for i in range(0, len(padded_msg), 64)]
        assert len(M) == len(padded_msg) / 64

        for i in range(len(M)):
            assert len(M[i]) == 64  # sanity check

        # do hashing voodoo
        for i in range(len(M)):
            W = [
                int.from_bytes(M[i][j:j+4], byteorder="big")
                for j in range(0, len(M[i]), 4)
            ]
            assert len(W) == 16
            assert type(W[0]) == int
            assert W[0] == (M[i][0] << 24) + (M[i][1] << 16) + (M[i][2] << 8) + M[i][3]

            for t in range(16, 80):
                W.append(Sha1._S(1, W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16]))

            A, B, C, D, E = H
            for t in range(80):
                TEMP = (((((((Sha1._S(5, A) + Sha1._f(t, B, C, D)) & 0xFFFFFFFF) + E) & 0xFFFFFFFF) + W[t]) & 0xFFFFFFFF) + Sha1._K(t)) & 0xFFFFFFFF
                assert TEMP == (Sha1._S(5, A) + Sha1._f(t, B, C, D) + E + W[t] + Sha1._K(t)) & 0xFFFFFFFF
                E = D
                D = C
                C = Sha1._S(30, B)
                B = A
                A = TEMP

            H = [
                (H[0] + A) & 0xFFFFFFFF,
                (H[1] + B) & 0xFFFFFFFF,
                (H[2] + C) & 0xFFFFFFFF,
                (H[3] + D) & 0xFFFFFFFF,
                (H[4] + E) & 0xFFFFFFFF,
            ]

        # craft the hex digest
        digest = ""
        for h in H:
            strh = hex(h)[2:]
            strh = "0" * (8 - len(strh)) + strh
            digest += strh
        return digest

    @staticmethod
    def _f(t, B, C, D):
        if t >= 0 and t <= 19:    return ((B & C) | ((~B) & D)) & 0xFFFFFFFF
        elif t >= 20 and t <= 39: return (B ^ C ^ D) & 0xFFFFFFFF
        elif t >= 40 and t <= 59: return ((B & C) | (B & D) | (C & D)) & 0xFFFFFFFF
        elif t >= 60 and t <= 79: return (B ^ C ^ D) & 0xFFFFFFFF
        assert False

    @staticmethod
    def _K(t):
        if t >= 0 and t <= 19:    return 0x5A827999
        elif t >= 20 and t <= 39: return 0x6ED9EBA1
        elif t >= 40 and t <= 59: return 0x8F1BBCDC
        elif t >= 60 and t <= 79: return 0xCA62C1D6
        assert False

    @staticmethod
    def _S(n, X):
        assert n >= 0 and n < 32, "n not in range"
        assert (X >> 32) == 0, "X too large"
        result = ((X << n) | (X >> (32-n))) & 0xFFFFFFFF
        assert (result >> 32) == 0, "result too large"
        return result
