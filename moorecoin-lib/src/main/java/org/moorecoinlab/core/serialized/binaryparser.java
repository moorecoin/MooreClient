package org.moorecoinlab.core.serialized;

import org.moorecoinlab.core.fields.field;
import org.ripple.bouncycastle.util.encoders.hex;

public class binaryparser {
    protected int size;
    protected byte[] bytes;
    protected int cursor = 0;

    public binaryparser(byte[] bytes) {
        this.size = bytes.length;
        this.bytes = bytes;
    }

    public binaryparser(int size) {
        this.size = size;
    }

    public binaryparser(string hex) {
        this(hex.decode(hex));
    }

    public void skip(int n) {
        cursor += n;
    }

    public byte readone() {
        return bytes[cursor++];
    }
    protected byte[] read(int n, boolean advance) {
        byte[] ret = new byte[n];
        system.arraycopy(bytes, cursor, ret, 0, n);
        if (advance) {
            cursor += n;
        }
        return ret;
    }

    public byte[] read(int n) {
        return read(n, true);
    }

    public field readfield() {
        int fieldcode = readfieldcode();
        field field = field.fromcode(fieldcode);
        if (field == null) {
            throw new illegalstateexception("couldn't parse field from " +
                    integer.tohexstring(fieldcode));
        }

        return field;
    }

    public int readfieldcode() {
        byte tagbyte = readone();

        int typebits = (tagbyte & 0xff) >>> 4;
        if (typebits == 0) typebits = readone();

        int fieldbits = tagbyte & 0x0f;
        if (fieldbits == 0) fieldbits = readone();

        return (typebits << 16 | fieldbits);
    }

    public boolean end() {
        return cursor >= size; // greater guard against infinite loops
    }

    public int pos() {
        return cursor;
    }

    public int readoneint() {
        return readone() & 0xff;
    }

    public int readvllength() {
        int b1 = readoneint();
        int result;

        if (b1 <= 192) {
            result = b1;
        } else if (b1 <= 240) {
            int b2 = readoneint();
            result = 193 + (b1 - 193) * 256 + b2;
        } else if (b1 <= 254) {
            int b2 = readoneint();
            int b3 = readoneint();
            result = 12481 + (b1 - 241) * 65536 + b2 * 256 + b3;
        } else {
            throw new runtimeexception("invalid varint length indicator");
        }

        return result;
    }

    public int size() {
        return size;
    }

}
