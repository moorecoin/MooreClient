package org.moorecoinlab.core.hash;

import org.moorecoinlab.core.fields.field;
import org.moorecoinlab.core.fields.typedfields;
import org.moorecoinlab.core.serialized.bytessink;

public class hash128 extends hash<hash128> {
    public hash128(byte[] bytes) {
        super(bytes, 16);
    }

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
    public static class translator extends hashtranslator<hash128> {
        @override
        public hash128 newinstance(byte[] b) {
            return new hash128(b);
        }

        @override
        public int bytewidth() {
            return 16;
        }
    }
    public static translator translate = new translator();

    public static typedfields.hash128field hash128field(final field f) {
        return new typedfields.hash128field(){ @override public field getfield() {return f;}};
    }

    static public typedfields.hash128field emailhash = hash128field(field.emailhash);

}
