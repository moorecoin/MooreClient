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

public class pathset extends arraylist<pathset.path> implements serializedtype {
    public static byte path_separator_byte = (byte) 0xff;
    public static byte pathset_end_byte = (byte) 0x00;

    public pathset(){}

    public static class hop {
        public static byte type_account  = (byte) 0x01;
        public static byte type_currency = (byte) 0x10;
        public static byte type_issuer   = (byte) 0x20;
        public static final int type_account_currency_issuer = type_currency | type_account | type_issuer;
        public static final int type_account_currency = type_currency | type_account;
        public static int valid_type_mask =  ~(type_account | type_currency | type_issuer);

        public accountid account;
        public accountid issuer;
        public currency currency;
        private int type;

        public boolean hasissuer() {
            return issuer   != null;
        }
        public boolean hascurrency() {
            return currency != null;
        }
        public boolean hasaccount() {
            return account != null;
        }

        public int gettype() {
            if (type == 0) {
                synthesizetype();
            }
            return type;
        }

        static public hop fromjsonobject(jsonobject json) {
            hop hop = new hop();
            try {
                if (json.has("account")) {
                    hop.account = accountid.fromaddress(json.getstring("account"));
                }
                if (json.has("issuer")) {
                    hop.issuer = accountid.fromaddress(json.getstring("issuer"));
                }
                if (json.has("currency")) {
                    hop.currency = currency.fromstring(json.getstring("currency"));
                }
                if (json.has("type")) {
                    hop.type = json.getint("type");
                }

            } catch (jsonexception e) {
                throw new runtimeexception(e);
            }
            return hop;
        }

        public void synthesizetype() {
            type = 0;

            if (hasaccount()) type |= type_account;
            if (hascurrency()) type |= type_currency;
            if (hasissuer()) type |= type_issuer;
        }

        public jsonobject tojsonobject() {
            jsonobject object = new jsonobject();
            try {
                object.put("type", gettype());

                if (hasaccount()) object.put("account", account.tojson());
                if (hasissuer()) object.put("issuer", issuer.tojson());
                if (hascurrency()) object.put("currency", currency.tojson());

            } catch (jsonexception e) {
                throw new runtimeexception(e);
            }
            return object;
        }
    }
    public static class path extends arraylist<hop> {
        static public path fromjsonarray(jsonarray array) {
            path path = new path();
            int nhops = array.length();
            for (int i = 0; i < nhops; i++) {
                try {
                    jsonobject hop = array.getjsonobject(i);
                    path.add(hop.fromjsonobject(hop));
                } catch (jsonexception e) {
                    throw new runtimeexception(e);
                }
            }

            return path;
        }
        public jsonarray tojsonarray() {
            jsonarray array = new jsonarray();
            for (hop hop : this) {
                array.put(hop.tojsonobject());
            }
            return array;
        }
    }

    public jsonarray tojsonarray() {
        jsonarray array = new jsonarray();
        for (path path : this) {
            array.put(path.tojsonarray());
        }
        return array;
    }

    // serializedtype interface implementation
    @override
    public object tojson() {
        return tojsonarray();
    }

    @override
    public void tobytessink(bytessink buffer) {
        int n = 0;
        for (path path : this) {
            if (n++ != 0) {
                buffer.add(path_separator_byte);
            }
            for (hop hop : path) {
                int type = hop.gettype();
                buffer.add((byte) type);
                if (hop.hasaccount()) {
                    buffer.add(hop.account.bytes());
                }
                if (hop.hascurrency()) {
                    buffer.add(hop.currency.bytes());
                }
                if (hop.hasissuer()) {
                    buffer.add(hop.issuer.bytes());
                }
            }
        }
        buffer.add(pathset_end_byte);
    }

    @override
    public string tohex() {
        return translate.tohex(this);
    }

    @override
    public byte[] tobytes() {
        return translate.tobytes(this);
    }


    public static class translator extends typetranslator<pathset> {
        @override
        public pathset fromparser(binaryparser parser, integer hint) {
            pathset pathset = new pathset();
            pathset.path path = null;
            while (!parser.end()) {
                byte type = parser.readone();
                if (type == pathset_end_byte) {
                    break;
                }
                if (path == null) {
                    path = new pathset.path();
                    pathset.add(path);
                }
                if (type == path_separator_byte) {
                    path = null;
                    continue;
                }

                pathset.hop hop = new pathset.hop();
                path.add(hop);
                if ((type & hop.type_account) != 0) {
                    hop.account = accountid.translate.fromparser(parser);
                }
                if ((type & hop.type_currency) != 0) {
                    hop.currency = currency.translate.fromparser(parser);
                }
                if ((type & hop.type_issuer) != 0) {
                    hop.issuer = accountid.translate.fromparser(parser);
                }
            }

            return pathset;
        }

        @override
        public pathset fromjsonarray(jsonarray array) {
            pathset paths = new pathset();

            int npaths = array.length();

            for (int i = 0; i < npaths; i++) {
                try {
                    jsonarray path = array.getjsonarray(i);
                    paths.add(path.fromjsonarray(path));
                } catch (jsonexception e) {
                    throw new runtimeexception(e);
                }
            }

            return paths;
        }
    }
    static public translator translate = new translator();

    public static typedfields.pathsetfield pathsetfield(final field f) {
        return new typedfields.pathsetfield(){ @override public field getfield() {return f;}};
    }
    static public typedfields.pathsetfield paths = pathsetfield(field.paths);
}
