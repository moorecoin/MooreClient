package org.moorecoinlab.core.uint;

import org.moorecoinlab.core.fields.field;
import org.moorecoinlab.core.fields.typedfields;
import org.moorecoinlab.core.serialized.bytessink;
import org.moorecoinlab.core.serialized.typetranslator;

import java.math.biginteger;

public class uint64 extends uint<uint64> {
    public static typetranslator<uint64> translate = new uinttranslator<uint64>() {
        @override
        public uint64 newinstance(biginteger i) {
            return new uint64(i);
        }

        @override
        public int bytewidth() {
            return 8;
        }
    };

    public uint64(byte[] bytes) {
        super(bytes);
    }

    public uint64(biginteger value) {
        super(value);
    }

    public uint64(number s) {
        super(s);
    }

    public uint64(string s) {
        super(s);
    }

    public uint64(string s, int radix) {
        super(s, radix);
    }

    @override
    public int getbytewidth() {
        return 8;
    }

    @override
    public uint64 instancefrom(biginteger n) {
        return new uint64(n);
    }

    @override
    public biginteger value() {
        return biginteger();
    }

    private uint64(){}

    private static typedfields.uint64field int64field(final field f) {
        return new typedfields.uint64field(){ @override public field getfield() {return f;}};
    }

    static public typedfields.uint64field indexnext = int64field(field.indexnext);
    static public typedfields.uint64field indexprevious = int64field(field.indexprevious);
    static public typedfields.uint64field booknode = int64field(field.booknode);
    static public typedfields.uint64field ownernode = int64field(field.ownernode);
    static public typedfields.uint64field basefee = int64field(field.basefee);
    static public typedfields.uint64field exchangerate = int64field(field.exchangerate);
    static public typedfields.uint64field lownode = int64field(field.lownode);
    static public typedfields.uint64field highnode = int64field(field.highnode);

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
