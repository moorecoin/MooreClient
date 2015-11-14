package org.moorecoinlab.core;

import org.moorecoinlab.core.fields.field;
import org.moorecoinlab.core.fields.hasfield;
import org.moorecoinlab.core.fields.type;
import org.moorecoinlab.core.fields.typedfields;
import org.moorecoinlab.core.formats.format;
import org.moorecoinlab.core.formats.leformat;
import org.moorecoinlab.core.formats.txformat;
import org.moorecoinlab.core.hash.hash128;
import org.moorecoinlab.core.hash.hash160;
import org.moorecoinlab.core.hash.hash256;
import org.moorecoinlab.core.serialized.*;
import org.moorecoinlab.core.serialized.enums.engineresult;
import org.moorecoinlab.core.serialized.enums.ledgerentrytype;
import org.moorecoinlab.core.serialized.enums.transactiontype;
import org.moorecoinlab.core.uint.uint16;
import org.moorecoinlab.core.uint.uint32;
import org.moorecoinlab.core.uint.uint64;
import org.moorecoinlab.core.uint.uint8;
import org.json.jsonexception;
import org.json.jsonobject;

import java.util.iterator;
import java.util.treemap;

public class stobject implements serializedtype, iterable<field> {
    // internally the fields are stored in a treemap
    public static class fieldsmap extends treemap<field, serializedtype> {}
    // there's no nice predicates
    public static interface fieldfilter {
        boolean evaluate(field a);
    }

    protected fieldsmap fields;
    public format format;

    public stobject() {
        fields = new fieldsmap();
    }
    public stobject(fieldsmap fieldsmap) {
        fields = fieldsmap;
    }

    public static stobject fromjson(string offerjson) {
        try {
            return fromjsonobject(new jsonobject(offerjson));
        } catch (jsonexception e) {
            throw new runtimeexception(e);
        }
    }
    public static stobject fromjsonobject(jsonobject json) {
        return translate.fromjsonobject(json);
    }
    public static stobject fromhex(string hex) {
        return stobject.translate.fromhex(hex);
    }

    @override
    public iterator<field> iterator() {
        return fields.keyset().iterator();
    }

    public string prettyjson() {
        try {
            return translate.tojsonobject(this).tostring(4);
        } catch (jsonexception e) {
            throw new runtimeexception(e);
        }
    }

    /**
     * @return a subclass of stobject using the same fields
     */
    public static stobject formatted(stobject source) {
        return stobjectformatter.doformatted(source);

    }

    public format getformat() {
        if (format == null) computeformat();
        return format;
    }

    public void setformat(format format) {
        this.format = format;
    }

    private void computeformat() {
        uint16 tt = get(uint16.transactiontype);
        if (tt != null) {
            setformat(txformat.fromnumber(tt));
        }
        uint16 let = get(uint16.ledgerentrytype);
        if (let != null) {
            setformat(leformat.fromnumber(let));
        }
    }

    public fieldsmap getfields() {
        return fields;
    }

    public serializedtype get(field field) {
        return fields.get(field);
    }

    public static engineresult engineresult(stobject obj) {
        return (engineresult) obj.get(field.transactionresult);
    }

    static public ledgerentrytype ledgerentrytype(stobject obj) {
        return (ledgerentrytype) obj.get(field.ledgerentrytype);
    }

    public static transactiontype transactiontype(stobject obj) {
        return (transactiontype) obj.get(field.transactiontype);
    }

    public serializedtype remove(field f) {
        return fields.remove(f);
    }

    public boolean has(field f) {
        return fields.containskey(f);
    }

    public <t extends hasfield> boolean has(t hf) {
        return has(hf.getfield());
    }

    public void put (typedfields.uint8field f, uint8 o) {put(f.getfield(), o);}
    public void put (typedfields.vector256field f, vector256 o) {put(f.getfield(), o);}
    public void put (typedfields.variablelengthfield f, variablelength o) {put(f.getfield(), o);}
    public void put (typedfields.uint64field f, uint64 o) {put(f.getfield(), o);}
    public void put (typedfields.uint32field f, uint32 o) {put(f.getfield(), o);}
    public void put (typedfields.uint16field f, uint16 o) {put(f.getfield(), o);}
    public void put (typedfields.pathsetfield f, pathset o) {put(f.getfield(), o);}
    public void put (typedfields.stobjectfield f, stobject o) {put(f.getfield(), o);}
    public void put (typedfields.hash256field f, hash256 o) {put(f.getfield(), o);}
    public void put (typedfields.hash160field f, hash160 o) {put(f.getfield(), o);}
    public void put (typedfields.hash128field f, hash128 o) {put(f.getfield(), o);}
    public void put (typedfields.starrayfield f, starray o) {put(f.getfield(), o);}
    public void put (typedfields.amountfield f, amount o) {put(f.getfield(), o);}
    public void put (typedfields.accountidfield f, accountid o) {put(f.getfield(), o);}

    public <t extends hasfield> void puttranslated(t f, object value) {
        puttranslated(f.getfield(), value);
    }

    public void put(field f, serializedtype value) {
        fields.put(f, value);
    }

    public void puttranslated(field f, object value) {
        typetranslator typetranslator = translators.forfield(f);
        serializedtype st = null;
        try {
            st = typetranslator.fromvalue(value);
        } catch (exception e) {
            throw new runtimeexception("couldn't put `" +value+ "` into field `" + f + "`\n" + e.tostring());
        }
        fields.put(f, st);
    }

    public accountid get(typedfields.accountidfield f) {
        return (accountid) get(f.getfield());
    }

    public amount get(typedfields.amountfield f) {
        return (amount) get(f.getfield());
    }

    public starray get(typedfields.starrayfield f) {
        return (starray) get(f.getfield());
    }

    public hash128 get(typedfields.hash128field f) {
        return (hash128) get(f.getfield());
    }

    public hash160 get(typedfields.hash160field f) {
        return (hash160) get(f.getfield());
    }

    public hash256 get(typedfields.hash256field f) {
        return (hash256) get(f.getfield());
    }

    public stobject get(typedfields.stobjectfield f) {
        return (stobject) get(f.getfield());
    }

    public pathset get(typedfields.pathsetfield f) {
        return (pathset) get(f.getfield());
    }

    public uint16 get(typedfields.uint16field f) {
        return (uint16) get(f.getfield());
    }

    public uint32 get(typedfields.uint32field f) {
        return (uint32) get(f.getfield());
    }

    public uint64 get(typedfields.uint64field f) {
        return (uint64) get(f.getfield());
    }

    public uint8 get(typedfields.uint8field f) {
        return (uint8) get(f.getfield());
    }

    public vector256 get(typedfields.vector256field f) {
        return (vector256) get(f.getfield());
    }

    public variablelength get(typedfields.variablelengthfield f) {
        return (variablelength) get(f.getfield());
    }

    // serializedtypes implementation
    @override
    public object tojson() {
        return translate.tojson(this);
    }

    public jsonobject tojsonobject() {
        return translate.tojsonobject(this);
    }

    public byte[] tobytes() {
        return translate.tobytes(this);
    }

    @override
    public string tohex() {
        return translate.tohex(this);
    }

    public void tobytessink(bytessink to, fieldfilter p) {
        binaryserializer serializer = new binaryserializer(to);

        for (field field : this) {
            if (p.evaluate(field)) {
                serializedtype value = fields.get(field);
                serializer.add(field, value);
            }
        }
    }
    @override
    public void tobytessink(bytessink to) {
        tobytessink(to, new fieldfilter() {
            @override
            public boolean evaluate(field field) {
                return field.isserialized();
            }
        });
    }

    public static class translator extends typetranslator<stobject> {

        @override
        public stobject fromparser(binaryparser parser, integer hint) {
            stobject so = new stobject();
            typetranslator<serializedtype> tr;
            serializedtype st;
            field field;
            integer sizehint;

            // hint, is how many bytes to parse
            if (hint != null) {
                // end hint
                hint = parser.pos() + hint;
            }

            while (!(parser.end() || hint != null && parser.pos() >= hint)) {
                field = parser.readfield();
                if (field == field.objectendmarker) {
                    break;
                }
                tr = translators.forfield(field);
                sizehint = field.isvlencoded() ? parser.readvllength() : null;
                st = tr.fromparser(parser, sizehint);
                if (st == null) {
                    throw new illegalstateexception("parsed " + field + " as null");
                }
                so.put(field, st);
            }

            return stobject.formatted(so);
        }

        @override
        public object tojson(stobject obj) {
            return tojsonobject(obj);
        }

        @override
        public jsonobject tojsonobject(stobject obj) {
            jsonobject json = new jsonobject();

            for (field f : obj) {
                try {
                    serializedtype obj1 = obj.get(f);
                    object object = obj1.tojson();
                    json.put(f.name(), object);
                } catch (jsonexception e) {
                    throw new runtimeexception(e);
                }
            }

            return json;
        }

        @override
        public stobject fromjsonobject(jsonobject jsonobject) {
            stobject so = new stobject();

            iterator keys = jsonobject.keys();
            while (keys.hasnext()) {
                string key = (string) keys.next();
                try {
                    object value   = jsonobject.get(key);
                    field fieldkey = field.fromstring(key);
                    if (fieldkey == null) {
                        continue;
                    }
                    so.puttranslated(fieldkey, value);
                } catch (jsonexception e) {
                    throw new runtimeexception(e);
                }            }
            return stobject.formatted(so);
        }
    }

    public int size() {
        return fields.size();
    }

    static public translator translate = new translator();

    public static typedfields.stobjectfield stobjectfield(final field f) {
        return new typedfields.stobjectfield() {@override public field getfield() {return f; } };
    }

    static public typedfields.stobjectfield transactionmetadata = stobjectfield(field.transactionmetadata);
    static public typedfields.stobjectfield creatednode = stobjectfield(field.creatednode);
    static public typedfields.stobjectfield deletednode = stobjectfield(field.deletednode);
    static public typedfields.stobjectfield modifiednode = stobjectfield(field.modifiednode);
    static public typedfields.stobjectfield previousfields = stobjectfield(field.previousfields);
    static public typedfields.stobjectfield finalfields = stobjectfield(field.finalfields);
    static public typedfields.stobjectfield newfields = stobjectfield(field.newfields);
    static public typedfields.stobjectfield templateentry = stobjectfield(field.templateentry);

    public static class translators {
        private static typetranslator fortype(type type) {
            switch (type) {

                case stobject:      return translate;
                case amount:        return amount.translate;
                case uint16:        return uint16.translate;
                case uint32:        return uint32.translate;
                case uint64:        return uint64.translate;
                case hash128:       return hash128.translate;
                case hash256:       return hash256.translate;
                case variablelength:return variablelength.translate;
                case accountid:     return accountid.translate;
                case starray:       return starray.translate;
                case uint8:         return uint8.translate;
                case hash160:       return hash160.translate;
                case pathset:       return pathset.translate;
                case vector256:     return vector256.translate;

                default:            throw new runtimeexception("unknown type");
            }
        }

        public static typetranslator<serializedtype> forfield(field field) {
            if (field.tag == null) {
                switch (field) {
                    case ledgerentrytype:
                        field.tag = ledgerentrytype.translate;
                        break;
                    case transactiontype:
                        field.tag = transactiontype.translate;
                        break;
                    case transactionresult:
                        field.tag = engineresult.translate;
                        break;
                    default:
                        field.tag = fortype(field.gettype());
                        break;
                }
            }
            return getcastedtag(field);
        }

        @suppresswarnings("unchecked")
        private static typetranslator<serializedtype> getcastedtag(field field) {
            return (typetranslator<serializedtype>) field.tag;
        }
    }
}
