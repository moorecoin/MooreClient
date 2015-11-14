package org.moorecoinlab.core.hash;

import org.moorecoinlab.core.fields.field;
import org.moorecoinlab.core.fields.typedfields;
import org.moorecoinlab.core.hash.prefixes.hashprefix;
import org.moorecoinlab.core.hash.prefixes.prefix;
import org.moorecoinlab.core.serialized.bytessink;

import java.math.biginteger;
import java.util.treemap;

public class hash256 extends hash<hash256> {

    public static final biginteger bookbasesize = new biginteger("10000000000000000", 16);
    public static class hash256map<value> extends treemap<hash256, value> {
        public hash256map(hash256map<value> cache) {
            super(cache);
        }
        public hash256map() {

        }
    }
    public static final hash256 zero_256 = new hash256(new byte[32]);

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

    public boolean iszero() {
        return equals(hash256.zero_256);
    }

    public boolean isnonzero() {
        return !iszero();
    }

    public static hash256 fromhex(string s) {
        return translate.fromhex(s);
    }

    public hash256(byte[] bytes) {
        super(bytes, 32);
    }

    public static hash256 signinghash(byte[] blob) {
        return prefixedhalfsha512(hashprefix.txsign, blob);
    }

    public static hash256 prefixedhalfsha512(prefix prefix, byte[] blob) {
        halfsha512 messagedigest = halfsha512.prefixed256(prefix);
        messagedigest.update(blob);
        return messagedigest.finish();
    }

    public int nibblet(int depth) {
        int byte_ix = depth > 0 ? depth / 2 : 0;
        int b = super.hash[byte_ix];
        if (depth % 2 == 0) {
            b = (b & 0xf0) >> 4;
        } else {
            b = b & 0x0f;
        }
        return b;
    }

    public static class translator extends hashtranslator<hash256> {
        @override
        public hash256 newinstance(byte[] b) {
            return new hash256(b);
        }

        @override
        public int bytewidth() {
            return 32;
        }
    }
    public static translator translate = new translator();

    public static typedfields.hash256field hash256field(final field f) {
        return new typedfields.hash256field(){ @override public field getfield() {return f;}};
    }

    static public typedfields.hash256field ledgerhash = hash256field(field.ledgerhash);
    static public typedfields.hash256field parenthash = hash256field(field.parenthash);
    static public typedfields.hash256field transactionhash = hash256field(field.transactionhash);
    static public typedfields.hash256field accounthash = hash256field(field.accounthash);
    static public typedfields.hash256field previoustxnid = hash256field(field.previoustxnid);
    static public typedfields.hash256field accounttxnid = hash256field(field.accounttxnid);
    static public typedfields.hash256field ledgerindex = hash256field(field.ledgerindex);
    static public typedfields.hash256field walletlocator = hash256field(field.walletlocator);
    static public typedfields.hash256field rootindex = hash256field(field.rootindex);
    static public typedfields.hash256field bookdirectory = hash256field(field.bookdirectory);
    static public typedfields.hash256field invoiceid = hash256field(field.invoiceid);
    static public typedfields.hash256field nickname = hash256field(field.nickname);
    static public typedfields.hash256field amendment = hash256field(field.amendment);
    static public typedfields.hash256field ticketid = hash256field(field.ticketid);

    static public typedfields.hash256field hash = hash256field(field.hash);
    static public typedfields.hash256field index = hash256field(field.index);
}
