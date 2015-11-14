package org.moorecoinlab.core;

import org.moorecoinlab.core.exception.moorecoinexception;
import org.moorecoinlab.core.fields.field;
import org.moorecoinlab.core.fields.typedfields;
import org.moorecoinlab.core.hash.b58;
import org.moorecoinlab.core.hash.hash160;
import org.moorecoinlab.core.serialized.binaryparser;
import org.moorecoinlab.core.serialized.bytessink;
import org.moorecoinlab.core.serialized.typetranslator;
import org.moorecoinlab.core.uint.uint32;
import org.moorecoinlab.crypto.ecdsa.ikeypair;
import org.moorecoinlab.crypto.ecdsa.seed;
import org.ripple.bouncycastle.util.encoders.hex;

import java.util.hashmap;
import java.util.map;

public class accountid extends hash160 {
    final public string address;

    /**
     * constructor of accountid
     * @param bytes   must be sha256_ripemd160 format
     */
    public accountid(byte[] bytes) {
        this(bytes, encodeaddress(bytes));
    }

    public accountid(byte[] bytes, string address) {
        super(bytes);
        this.address = address;
    }

    @override
    public int hashcode() {
        return address.hashcode();
    }

    public static accountid neutral,  vrp_issuer;
    public static accountid vbc_0,  vbc_1;

    static {
        vrp_issuer = frominteger(0);
        neutral = frominteger(1);
        vbc_0 = frominteger(10000);
        vbc_1 = frominteger(20000);
//        system.out.println("account_1 : " + neutral.address);
//        system.out.println("vbc_0     : " + vbc_0.address);
//        system.out.println("vbc_1     : " + vbc_1.address);
    }

    @override
    public string tostring() {
        return address;
    }

    //@deprecated
    static public accountid fromseedbytes(byte[] seed) {
        return fromkeypair(seed.getkeypair(seed));
    }

    public static accountid fromkeypair(ikeypair kp) {
        byte[] bytes = kp.sha256_ripemd160_pub();
        return new accountid(bytes, encodeaddress(bytes));
    }

    private static string encodeaddress(byte[] a) {
        if(a.length != 20)  // added by fau
            throw new moorecoinexception("encodeaddress() param length must be 20(ripemd160)!");
        return b58.getinstance().encodeaddress(a);
    }

    static public accountid frominteger(integer n) {
        // the hash160 will extend the address
        return frombytes(new hash160(new uint32(n).tobytearray()).bytes());
    }

    public static accountid frombytes(byte[] bytes) {
        return new accountid(bytes, encodeaddress(bytes));
    }

    static public accountid fromaddress(string address) throws moorecoinexception {
        byte[] bytes = b58.getinstance().decodeaddress(address);
        return new accountid(bytes, address);
    }

    static public accountid fromaddressbytes(byte[] bytes) {
        return frombytes(bytes);
    }

    public issue issue(string code) {
        return new issue(currency.fromstring(code), this);
    }

    @override
    public object tojson() {
        return tostring();
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
        to.add(bytes());
    }

    public boolean lessthan(accountid from) {
        return compareto(from) == -1;
    }

    public static class translator extends typetranslator<accountid> {
        @override
        public accountid fromparser(binaryparser parser, integer hint) {
            if (hint == null) {
                hint = 20;
            }
            return accountid.fromaddressbytes(parser.read(hint));
        }

        @override
        public string tostring(accountid obj) {
            return obj.tostring();
        }

        @override
        public accountid fromstring(string value) {
            return accountid.fromstring(value);
        }
    }

    public static accountid fromstring(string value) throws moorecoinexception {
        if (value.length() == 160 / 4) {
            return fromaddressbytes(hex.decode(value));
        } else {
            if (value.startswith("r") && value.length() >= 26) {
                return fromaddress(value);
            }
            // this is potentially dangerous but fromstring in
            // generic sense is used by amount for parsing strings
            return accountforpassphrase(value);
        }
    }

    static public map<string, accountid> accounts = new hashmap<string, accountid>();

    public static accountid accountforpassphrase(string value) {

        if (accounts.get(value) == null) {
            accounts.put(value, accountforpass(value));
        }

        return accounts.get(value);
    }

    private static accountid accountforpass(string value) {
        return accountid.fromseedbytes(seed.passphrasetoseedbytes(value));
    }

    static {
        accounts.put("root", accountforpass("masterpassphrase"));
    }

    public boolean isnativeissuer() {
        return equals(vrp_issuer);
    }

    static public translator translate = new translator();

    public static typedfields.accountidfield accountfield(final field f) {
        return new typedfields.accountidfield() {
            @override
            public field getfield() {
                return f;
            }
        };
    }

    static public typedfields.accountidfield account = accountfield(field.account);
    static public typedfields.accountidfield owner = accountfield(field.owner);
    static public typedfields.accountidfield destination = accountfield(field.destination);
    static public typedfields.accountidfield issuer = accountfield(field.issuer);
    static public typedfields.accountidfield target = accountfield(field.target);
    static public typedfields.accountidfield regularkey = accountfield(field.regularkey);
}
