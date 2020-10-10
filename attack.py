#!/usr/bin/env python3

# William Emmanuel
# SHA-1 Length Extension Attack

import oracle
import crypto
from struct import pack, unpack
import math

def get_initial_state(hash):
    b = bytes.fromhex(hash)
    return list(unpack(">5I", b))

def main(message, injection):
    # Get original tag
    original_tag = oracle.query(message)

    # Get initial hasher state by parsing digest
    state = get_initial_state()

    # Iterate all possible key lengths, 1 - 100
    for key_length in range(0, 110):
        hasher = crypto.Sha1()
        # Create original message payload, with unknown key of "****"
        original_message = b'*' * key_length + crypto.s2b(message)
        # Pad this message, removing key from beginning
        padded_original = hasher.pad_message(original_message)[key_length:]
        # Create our new message string, the original padded plus injection
        new_message = padded_original + crypto.s2b(injection)
        # Create a hash using extra padding and intial state
        extra_length = int(math.ceil((len(padded_original) + key_length) * 8 / 512.0)) * 512
        new_hash = hasher.sha1(crypto.s2b(injection), extra_length=extra_length, initial_state=state)
        # If the hash works, return it

        if oracle.check(new_message, new_hash):
            return crypto.b2s(new_message), new_hash
    return crypto.s2b(""), ""
