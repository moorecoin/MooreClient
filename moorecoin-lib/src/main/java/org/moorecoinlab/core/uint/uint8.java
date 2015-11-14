package org.moorecoinlab.core.uint;

import org.moorecoinlab.core.fields.field;
import org.moorecoinlab.core.fields.typedfields;
import org.moorecoinlab.core.serialized.bytessink;
import org.moorecoinlab.core.serialized.typetranslator;

import java.math.biginteger;

public class uint8 extends uint<uint8> {
    public static typetranslator<uint8> translate = new uinttranslator<uint8>() {
        @override
        public uint8 newinstance(biginteger i) {
            return new uint8(i);
        }

        @override
        public int bytewidth() {
            return 1;
        }
    };

    public uint8(byte[] bytes) {
        super(bytes);
    }

    public uint8(biginteger value) {
        super(value);
    }

    public uint8(number s) {
        super(s);
    }

    public uint8(string s) {
        super(s);
    }

    public uint8(string s, int radix) {
        super(s, radix);
    }

    @override
    public int getbytewidth() {
        return 1;
    }

    @override
    public uint8 instancefrom(biginteger n) {
        return new uint8(n);
    }

    @override
    public short value() {
        return shortvalue();
    }

    private uint8() {
    }

    private static typedfields.uint8field int8field(final field f) {
        return new typedfields.uint8field() {@override public field getfield() {return f; } };
    }

    static public typedfields.uint8field closeresolution = int8field(field.closeresolution);
    static public typedfields.uint8field templateentrytype = int8field(field.templateentrytype);
    static public typedfields.uint8field transactionresult = int8field(field.transactionresult);

    @override
    public object tojson() {
        return translate.tojson(this);
    }

    @override
    public byte[] tobytes() {
        return translate.tobytes(this);
    }

    @override
    public string tohex() {
        return translate.tohex(this);
    }

    @override
    public void tobytessink(bytessink to) {
        translate.tobytessink(this, to);
    }
}
