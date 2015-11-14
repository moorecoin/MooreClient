
package org.moorecoinlab.core;

import org.moorecoinlab.core.fields.field;
import org.moorecoinlab.core.fields.typedfields;
import org.moorecoinlab.core.serialized.binaryparser;
import org.moorecoinlab.core.serialized.bytessink;
import org.moorecoinlab.core.serialized.serializedtype;
import org.moorecoinlab.core.serialized.typetranslator;
import org.ripple.bouncycastle.util.encoders.hex;

public class variablelength implements serializedtype {
    public variablelength(byte[] bytes) {
        buffer = bytes;
    }

    byte[] buffer;

    @override
    public object tojson() {
        return translate.tojson(this);
    }

    @override
    public byte[] tobytes() {
        return buffer;
    }

    @override
    public string tohex() {
        return translate.tohex(this);
    }

    @override
    public void tobytessink(bytessink to) {
        translate.tobytessink(this, to);
    }

    public static variablelength frombytes(byte[] bytes) {
        return new variablelength(bytes);
    }

    public static class translator extends typetranslator<variablelength> {
        @override
        public variablelength fromparser(binaryparser parser, integer hint) {
            if (hint == null) {
                hint = parser.size() - parser.pos();
            }
            return new variablelength(parser.read(hint));
        }

        @override
        public object tojson(variablelength obj) {
            return tostring(obj);
        }

        @override
        public string tostring(variablelength obj) {
            return hex.tohexstring(obj.buffer);
        }

        @override
        public variablelength fromstring(string value) {
            return new variablelength(hex.decode(value));
        }

        @override
        public void tobytessink(variablelength obj, bytessink to) {
            to.add(obj.buffer);
        }
    }

    static public translator translate = new translator();

    public static typedfields.variablelengthfield variablelengthfield(final field f) {
        return new typedfields.variablelengthfield() {
            @override
            public field getfield() {
                return f;
            }
        };
    }

    static public typedfields.variablelengthfield publickey = variablelengthfield(field.publickey);
    static public typedfields.variablelengthfield messagekey = variablelengthfield(field.messagekey);
    static public typedfields.variablelengthfield signingpubkey = variablelengthfield(field.signingpubkey);
    static public typedfields.variablelengthfield txnsignature = variablelengthfield(field.txnsignature);
    static public typedfields.variablelengthfield generator = variablelengthfield(field.generator);
    static public typedfields.variablelengthfield signature = variablelengthfield(field.signature);
    static public typedfields.variablelengthfield domain = variablelengthfield(field.domain);
    static public typedfields.variablelengthfield fundcode = variablelengthfield(field.fundcode);
    static public typedfields.variablelengthfield removecode = variablelengthfield(field.removecode);
    static public typedfields.variablelengthfield expirecode = variablelengthfield(field.expirecode);
    static public typedfields.variablelengthfield createcode = variablelengthfield(field.createcode);

    static public typedfields.variablelengthfield memotype = variablelengthfield(field.memotype);
    static public typedfields.variablelengthfield memodata = variablelengthfield(field.memodata);
    static public typedfields.variablelengthfield memoformat = variablelengthfield(field.memoformat);
}
