package org.moorecoinlab.core;

import org.ripple.bouncycastle.crypto.digests.ripemd160digest;
import org.ripple.bouncycastle.util.encoders.hex;

import java.math.biginteger;
import java.security.messagedigest;
import java.security.nosuchalgorithmexception;

public class utils {
    private static final messagedigest digest;
    static {
        try {
            digest = messagedigest.getinstance("sha-256");
        } catch (nosuchalgorithmexception e) {
            throw new runtimeexception(e);  // can't happen.
        }
    }

    /**
     * see {@link utils#doubledigest(byte[], int, int)}.
     */
    public static byte[] doubledigest(byte[] input) {
        return doubledigest(input, 0, input.length);
    }

    /**
     * calculates the sha-256 hash of the given byte range, and then hashes the resulting hash again. this is
     * standard procedure in bitcoin. the resulting hash is in big endian form.
     */
    public static byte[] doubledigest(byte[] input, int offset, int length) {
        synchronized (digest) {
            digest.reset();
            digest.update(input, offset, length);
            byte[] first = digest.digest();
            return digest.digest(first);
        }
    }

    public static byte[] halfsha512(byte[] bytes) {
        byte[] hash = new byte[32];
        system.arraycopy(sha512(bytes), 0, hash, 0, 32);
        return hash;
    }

    public static byte[] quartersha512(byte[] bytes) {
        byte[] hash = new byte[16];
        system.arraycopy(sha512(bytes), 0, hash, 0, 16);
        return hash;
    }

    public static byte[] sha512(byte[] bytearrays) {
        messagedigest messagedigest;
        try {
            messagedigest = messagedigest.getinstance("sha-512");
        } catch (nosuchalgorithmexception e) {
            throw new runtimeexception(e);
        } catch (exception e) {
            throw new runtimeexception(e);
        }
        messagedigest.update(bytearrays);
        return messagedigest.digest();
    }

    public static byte[] sha256_ripemd160(byte[] input) {
        try {
            byte[] sha256 = messagedigest.getinstance("sha-256").digest(input);
            ripemd160digest digest = new ripemd160digest();
            digest.update(sha256, 0, sha256.length);
            byte[] out = new byte[20];
            digest.dofinal(out, 0);
            return out;
        } catch (nosuchalgorithmexception e) {
            throw new runtimeexception(e);  // cannot happen.
        }
    }

    public static string bighex(biginteger bn) {
        return hex.tohexstring(bn.tobytearray());
    }

    public static biginteger ubigint(byte[] bytes) {
        return new biginteger(1, bytes);
    }

    /**  get the lowest n bytes from source array */
    public static byte[] lowarray(byte[] src, int n) {
        if(n >= src.length) return src;
        int pos = src.length - n;
        byte[] des = new byte[n];
        system.arraycopy(src, pos, des, 0, n);
        return des;
    }
}
