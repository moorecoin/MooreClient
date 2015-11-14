package org.moorecoinlab.core.hash;

import org.moorecoinlab.core.hash.prefixes.prefix;
import org.moorecoinlab.core.serialized.bytessink;
import org.moorecoinlab.core.serialized.serializedtype;

import java.security.messagedigest;

public class halfsha512 implements bytessink {
    messagedigest messagedigest;

    public halfsha512() {
        try {
            messagedigest = messagedigest.getinstance("sha-512");
        } catch (exception e) {
            throw new runtimeexception(e);
        }
    }

    public static halfsha512 prefixed256(prefix bytes) {
        halfsha512 halfsha512 = new halfsha512();
        halfsha512.update(bytes);
        return halfsha512;
    }

    public void update(byte[] bytes) {
        messagedigest.update(bytes);
    }

    public void update(hash256 hash) {
        messagedigest.update(hash.bytes());
    }

    public messagedigest digest() {
        return messagedigest;
    }

    public hash256 finish() {
        byte[] half = digestbytes();
        return new hash256(half);
    }

    private byte[] digestbytes() {
        byte[] digest = messagedigest.digest();
        byte[] half = new byte[32];
        system.arraycopy(digest, 0, half, 0, 32);
        return half;
    }

    private hash256 makehash(byte[] half) {
        return new hash256(half);
    }

    @override
    public void add(byte abyte) {
        messagedigest.update(abyte);
    }

    @override
    public void add(byte[] bytes) {
        messagedigest.update(bytes);
    }

    public void update(prefix prefix) {
        messagedigest.update(prefix.bytes());
    }

    public halfsha512 add(serializedtype st) {
        st.tobytessink(this);
        return this;
    }
}
