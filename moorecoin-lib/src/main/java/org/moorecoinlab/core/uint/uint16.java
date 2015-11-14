package org.moorecoinlab.core.uint;

import org.moorecoinlab.core.fields.field;
import org.moorecoinlab.core.fields.typedfields;
import org.moorecoinlab.core.serialized.bytessink;
import org.moorecoinlab.core.serialized.typetranslator;

import java.math.biginteger;

public class uint16 extends uint<uint16> {
    public static typetranslator<uint16> translate = new uinttranslator<uint16>() {
        @override
        public uint16 newinstance(biginteger i) {
            return new uint16(i);
        }

        @override
        public int bytewidth() {
            return 2;
        }
    };

    public uint16(byte[] bytes) {
        super(bytes);
    }

    public uint16(biginteger value) {
        super(value);
    }

    public uint16(number s) {
        super(s);
    }

    public uint16(string s) {
        super(s);
    }

    public uint16(string s, int radix) {
        super(s, radix);
    }

    @override
    public int getbytewidth() {
        return 2;
    }

    @override
    public uint16 instancefrom(biginteger n) {
        return new uint16(n);
    }

    @override
    public integer value() {
        return intvalue();
    }

    public static typedfields.uint16field int16field(final field f) {
        return new typedfields.uint16field(){ @override public field getfield() {return f;}};
    }

    static public typedfields.uint16field ledgerentrytype = int16field(field.ledgerentrytype);
    static public typedfields.uint16field transactiontype = int16field(field.transactiontype);

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
