package org.moorecoinlab.crypto;

import java.security.messagedigest;
import java.security.nosuchalgorithmexception;

public class sha512 {
    messagedigest messagedigest;

    public sha512() {
        try {
            messagedigest = messagedigest.getinstance("sha-512");
        } catch (nosuchalgorithmexception e) {
            throw new runtimeexception(e);
        } catch (exception e) {
            throw new runtimeexception(e);
        }
    }

    public sha512(byte[] start) {
        this();
        add(start);
    }

    public sha512 add(byte[] bytes) {
        messagedigest.update(bytes);
        return this;
    }

    public sha512 add32(int i) {
        messagedigest.update((byte) ((i >>> 24) & 0xff));
        messagedigest.update((byte) ((i >>> 16) & 0xff));
        messagedigest.update((byte) ((i >>> 8)  & 0xff));
        messagedigest.update((byte) ((i)        & 0xff));
        return this;
    }

    private byte[] finishtaking(int size) {
        byte[] hash = new byte[size];
        system.arraycopy(messagedigest.digest(), 0, hash, 0, size);
        return hash;
    }

    public byte[] finish128() {
        return finishtaking(16);
    }

    public byte[] finish256() {
        return finishtaking(32);
    }

    public byte[] finish() {
        return messagedigest.digest();
    }
}
