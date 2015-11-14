package org.moorecoinlab.core.hash;

import org.moorecoinlab.core.accountid;
import org.moorecoinlab.core.fields.field;
import org.moorecoinlab.core.fields.typedfields;
import org.moorecoinlab.core.serialized.bytessink;

public class hash160 extends hash<hash160> {
    public hash160(byte[] bytes) {
        super(bytes, 20);
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

    public static class translator extends hashtranslator<hash160> {
        @override
        public hash160 newinstance(byte[] b) {
            return new hash160(b);
        }

        @override
        public int bytewidth() {
            return 20;
        }

        @override
        public hash160 fromstring(string value) {
            if (value.startswith("r")) {
                return newinstance(accountid.fromaddress(value).bytes());
            }
            return super.fromstring(value);
        }
    }
    public static translator translate = new translator();

    public static typedfields.hash160field hash160field(final field f) {
        return new typedfields.hash160field(){ @override public field getfield() {return f;}};
    }

    static public typedfields.hash160field takerpaysissuer = hash160field(field.takerpaysissuer);
    static public typedfields.hash160field takergetscurrency = hash160field(field.takergetscurrency);
    static public typedfields.hash160field takerpayscurrency = hash160field(field.takerpayscurrency);
    static public typedfields.hash160field takergetsissuer = hash160field(field.takergetsissuer);
}
