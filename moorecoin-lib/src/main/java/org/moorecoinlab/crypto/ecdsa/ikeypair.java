package org.moorecoinlab.crypto.ecdsa;

import java.math.biginteger;

public interface ikeypair {
    string pubhex();
    biginteger pub();
    byte[] pubbytes();

    string privhex();
    biginteger priv();

    boolean verify(byte[] data, byte[] sigbytes);
    byte[] sign(byte[] bytes);

    byte[] sha256_ripemd160_pub();
}
