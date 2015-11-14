package org.moorecoinlab.core;

import org.moorecoinlab.core.fields.field;
import org.moorecoinlab.core.fields.typedfields;
import org.moorecoinlab.core.serialized.binaryparser;
import org.moorecoinlab.core.serialized.bytessink;
import org.moorecoinlab.core.serialized.serializedtype;
import org.moorecoinlab.core.serialized.typetranslator;
import org.json.jsonarray;
import org.json.jsonexception;
import org.json.jsonobject;

import java.util.arraylist;

public class starray extends arraylist<stobject> implements serializedtype {
    public jsonarray tojsonarray() {
        jsonarray array = new jsonarray();

        for (stobject so : this) {
            array.put(so.tojson());
        }

        return array;
    }

    @override
    public object tojson() {
        return tojsonarray();
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
        for (stobject stobject : this) {
            stobject.tobytessink(to);
        }
    }

    public static class translator extends typetranslator<starray> {

        @override
        public starray fromparser(binaryparser parser, integer hint) {
            starray starray = new starray();
            while (!parser.end()) {
                field field = parser.readfield();
                if (field == field.arrayendmarker) {
                    break;
                }
                stobject outer = new stobject();
                // assert field.gettype() == type.stobject;
                outer.put(field, stobject.translate.fromparser(parser));
                starray.add(stobject.formatted(outer));
            }
            return starray;
        }

        @override
        public jsonarray tojsonarray(starray obj) {
            return obj.tojsonarray();
        }

        @override
        public starray fromjsonarray(jsonarray jsonarray) {
            starray arr = new starray();

            for (int i = 0; i < jsonarray.length(); i++) {
                try {
                    object o = jsonarray.get(i);
                    arr.add(stobject.fromjsonobject((jsonobject) o));

                } catch (jsonexception e) {
                    throw new runtimeexception(e);
                }
            }

            return arr;
        }
    }
    static public translator translate = new translator();

    public starray(){}

    public static typedfields.starrayfield starrayfield(final field f) {
        return new typedfields.starrayfield(){ @override public field getfield() {return f;}};
    }

    static public typedfields.starrayfield affectednodes = starrayfield(field.affectednodes);

    static public typedfields.starrayfield signingaccounts = starrayfield(field.signingaccounts);
    static public typedfields.starrayfield txnsignatures = starrayfield(field.txnsignatures);
    static public typedfields.starrayfield signatures = starrayfield(field.signatures);
    static public typedfields.starrayfield template = starrayfield(field.template);
    static public typedfields.starrayfield necessary = starrayfield(field.necessary);
    static public typedfields.starrayfield sufficient = starrayfield(field.sufficient);
}
