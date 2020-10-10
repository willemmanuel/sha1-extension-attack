# sha1-extension-attack
Implements a SHA-1 Merkle–Damgård length extension attack. Given a SHA-1 hash, this recreates hasher state and appends some attack string `injection`. This assumes a key of size between 1 and 100 bytes.
