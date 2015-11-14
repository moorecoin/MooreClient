package org.moorecoinlab.core.hash;

import org.moorecoinlab.core.serialized.binaryparser;
import org.moorecoinlab.core.serialized.bytessink;
import org.moorecoinlab.core.serialized.serializedtype;
import org.moorecoinlab.core.serialized.typetranslator;
import org.ripple.bouncycastle.util.encoders.hex;

import java.math.biginteger;
import java.util.arrays;

abstract public class hash<subclass extends hash> implements serializedtype, comparable<subclass> {
    protected final byte[] hash;
    protected int hashcode = -1;

    public hash(byte[] bytes, int size) {
        hash = normalizeandcheckhash(bytes, size);
    }

    @override
    public string tostring() {
        return new string(hex.encode(hash));
    }

    @override
    public int hashcode() {
        if (hashcode == -1) {
            hashcode = new biginteger(1, hash).hashcode();
        }
        return hashcode;
    }

    private byte[] normalizeandcheckhash(byte[] bytes, int size) {
        int length = bytes.length;
        if (length > size) {
            string simplename = "";

            throw new runtimeexception("hash length of " + length + "  is too wide for " + simplename);
        }
        if (length == size) {
            return bytes;
        } else {
            byte[] hash = new byte[size];
            //system.err.println("hash.normalizeandcheckhash() size=" + size + ", len=" + bytes.length + ", bytes=" + hex.tohexstring(hash));
            system.arraycopy(bytes, 0, hash, size - length, length);
            return hash;
        }
    }

    biginteger biginteger() {
        return new biginteger(1, hash);
    }

    public byte[] bytes() {
        return hash;
    }

    @override
    public boolean equals(object obj) {
        if (obj instanceof hash) {
            return arrays.equals(hash, ((hash) obj).hash);
        }

        return super.equals(obj);
    }

    @override
    public int compareto(subclass another) {
        int thislength = bytes().length;
        byte[] bytes = another.bytes();

        for (int i = 0; i < thislength; i++) {
            int cmp = (hash[i] & 0xff) - (bytes[i] & 0xff);
            if (cmp != 0) {
                return cmp;
            }
        }
        return 0;
    }

    public byte[] slice(int start) {
        return slice(start, 0);
    }

    public byte get(int i) {
        if (i < 0) i += hash.length;
        return hash[i];
    }

    public byte[] slice(int start, int end) {
        if (start < 0)  start += hash.length;
        if (end  <= 0)  end   += hash.length;

        int length = end - start;
        byte[] slice = new byte[length];

        system.arraycopy(hash, start, slice, 0, length);
        return slice;
    }

    static public abstract class hashtranslator<t extends hash> extends typetranslator<t> {

        public abstract t newinstance(byte[] b);
        public abstract int bytewidth();

        @override
        public t fromparser(binaryparser parser, integer hint) {
            return newinstance(parser.read(bytewidth()));
        }

        @override
        public object tojson(t obj) {
            return hex.tohexstring(obj.hash);
        }

        @override
        public t fromstring(string value) {
            return newinstance(hex.decode(value));
        }

        @override
        public void tobytessink(t obj, bytessink to) {
            to.add(obj.hash);
        }
    }
}
