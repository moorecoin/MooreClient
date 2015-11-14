package org.moorecoinlab.core;

import org.moorecoinlab.core.fields.field;
import org.moorecoinlab.core.fields.typedfields;
import org.moorecoinlab.core.hash.hash256;
import org.moorecoinlab.core.serialized.binaryparser;
import org.moorecoinlab.core.serialized.bytessink;
import org.moorecoinlab.core.serialized.serializedtype;
import org.moorecoinlab.core.serialized.typetranslator;
import org.json.jsonarray;
import org.json.jsonexception;
import org.ripple.bouncycastle.util.encoders.hex;

import java.util.arraylist;

public class vector256 extends arraylist<hash256> implements serializedtype {

    @override
    public object tojson() {
        return tojsonarray();
    }

    public jsonarray tojsonarray() {
        jsonarray array = new jsonarray();

        for (hash256 hash256 : this) {
            array.put(hash256.tostring());
        }

        return array;
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
        for (hash256 hash256 : this) {
            hash256.tobytessink(to);
        }
    }

    /**
     * this method puts the last element in the removed elements slot, and
     *  pops off the back, thus preserving contiguity but losing ordering.
     * @param ledgerindex the ledger entry index to remove
     */
    public void removeunstable(hash256 ledgerindex) {
        int i = indexof(ledgerindex);
        int last = size() - 1;
        hash256 lastindex = get(last);
        set(i, lastindex);
        remove(last);
    }

    public static class translator extends typetranslator<vector256> {
        @override
        public vector256 fromparser(binaryparser parser, integer hint) {
            vector256 vector256 = new vector256();
            if (hint == null) {
                hint = parser.size() - parser.pos();
            }
            for (int i = 0; i < hint / 32; i++) {
                vector256.add(hash256.translate.fromparser(parser));
            }

            return vector256;
        }

        @override
        public jsonarray tojsonarray(vector256 obj) {
            return obj.tojsonarray();
        }

        @override
        public vector256 fromjsonarray(jsonarray jsonarray) {
            vector256 vector = new vector256();

            for (int i = 0; i < jsonarray.length(); i++) {
                try {
                    string hex = jsonarray.getstring(i);
                    vector.add(new hash256(hex.decode(hex)));

                } catch (jsonexception e) {
                    throw new runtimeexception(e);
                }
            }

            return vector;
        }
    }
    static public translator translate = new translator();

    public vector256(){}

    public static typedfields.vector256field vector256field(final field f) {
        return new typedfields.vector256field(){ @override public field getfield() {return f;}};
    }
    
    static public typedfields.vector256field indexes = vector256field(field.indexes);
    static public typedfields.vector256field hashes = vector256field(field.hashes);
    static public typedfields.vector256field features = vector256field(field.features);
}
