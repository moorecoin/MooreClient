package org.moorecoinlab.btc;

/**
 * copyright 2011 google inc.
 *
 * licensed under the apache license, version 2.0 (the "license");
 * you may not use this file except in compliance with the license.
 * you may obtain a copy of the license at
 *
 *    http://www.apache.org/licenses/license-2.0
 *
 * unless required by applicable law or agreed to in writing, software
 * distributed under the license is distributed on an "as is" basis,
 * without warranties or conditions of any kind, either express or implied.
 * see the license for the specific language governing permissions and
 * limitations under the license.
 */

import org.moorecoinlab.btc.account.address;
import org.moorecoinlab.core.exception.moorecoinexception;
import org.ripple.bouncycastle.asn1.*;
import org.ripple.bouncycastle.asn1.sec.secnamedcurves;
import org.ripple.bouncycastle.asn1.x9.x9ecparameters;
import org.ripple.bouncycastle.crypto.asymmetriccipherkeypair;
import org.ripple.bouncycastle.crypto.generators.eckeypairgenerator;
import org.ripple.bouncycastle.crypto.params.ecdomainparameters;
import org.ripple.bouncycastle.crypto.params.eckeygenerationparameters;
import org.ripple.bouncycastle.crypto.params.ecprivatekeyparameters;
import org.ripple.bouncycastle.crypto.params.ecpublickeyparameters;
import org.ripple.bouncycastle.crypto.signers.ecdsasigner;
import org.ripple.bouncycastle.util.encoders.base64;

import java.io.bytearrayoutputstream;
import java.io.ioexception;
import java.io.serializable;
import java.math.biginteger;
import java.security.securerandom;

import static org.moorecoinlab.btc.bitutil.bytestohexstring;
import static org.moorecoinlab.btc.bitutil.parseashexorbase58;


/**
 * represents an elliptic curve keypair that we own and can use for signing transactions. currently,
 * bouncy castle is used. in future this may become an interface with multiple implementations using different crypto
 * libraries. the class also provides a static method that can verify a signature with just the public key.<p>
 */
public class eckey implements serializable {
    private static final ecdomainparameters ecparams;

    private static final securerandom securerandom;
    private static final long serialversionuid = -128224381592285821l;

    static {
        // all clients must agree on the curve to use by agreement. bitcoin uses secp256k1.
        x9ecparameters params = secnamedcurves.getbyname("secp256k1");
        ecparams = new ecdomainparameters(params.getcurve(), params.getg(), params.getn(), params.geth());
        securerandom = new securerandom();
    }

    // the two parts of the key. if "priv" is set, "pub" can always be calculated. if "pub" is set but not "priv", we
    // can only verify signatures not make them.
    // todo: redesign this class to use consistent internals and more efficient serialization.
    private biginteger priv;
    private byte[] pub;
    // creation time of the key in seconds since the epoch, or zero if the key was deserialized from a version that did
    // not have this field.
    private long creationtimeseconds;

    // transient because it's calculated on demand.
    transient private byte[] pubkeyhash;

    /** generates an entirely new keypair. */
    public eckey() {
        eckeypairgenerator generator = new eckeypairgenerator();
        eckeygenerationparameters keygenparams = new eckeygenerationparameters(ecparams, securerandom);
        generator.init(keygenparams);
        asymmetriccipherkeypair keypair = generator.generatekeypair();
        ecprivatekeyparameters privparams = (ecprivatekeyparameters) keypair.getprivate();
        ecpublickeyparameters pubparams = (ecpublickeyparameters) keypair.getpublic();
        priv = privparams.getd();
        // the public key is an encoded point on the elliptic curve. it has no meaning independent of the curve.
        pub = pubparams.getq().getencoded();
        creationtimeseconds = bitutil.now().gettime() / 1000;
    }

    /**
     * construct an eckey from an asn.1 encoded private key. these are produced by openssl and stored by the bitcoin
     * reference implementation in its wallet. note that this is slow because it requires an ec point multiply.
     */
    public static eckey fromasn1(byte[] asn1privkey) {
        return new eckey(extractprivatekeyfromasn1(asn1privkey));
    }

    /**
     * output this eckey as an asn.1 encoded private key, as understood by openssl or used by the bitcoin reference
     * implementation in its wallet storage format.
     */
    /*
    public byte[] toasn1() {
        try {
            bytearrayoutputstream baos = new bytearrayoutputstream(400);
            asn1outputstream encoder = new asn1outputstream(baos);
            dersequencegenerator seq = new dersequencegenerator(encoder);
            seq.addobject(new derinteger(1)); // version
            seq.addobject(new deroctetstring(priv.tobytearray()));
            seq.addobject(new dertaggedobject(0, secnamedcurves.getbyname("secp256k1").getderobject()));
            seq.addobject(new dertaggedobject(1, new derbitstring(getpubkey())));
            seq.close();
            encoder.close();
            return baos.tobytearray();
        } catch (ioexception e) {
            throw new runtimeexception(e);  // cannot happen, writing to memory stream.
        }
    }
    */
    /**
     * creates an eckey given either the private key only, the public key only, or both. if only the private key
     * is supplied, the public key will be calculated from it (this is slow). if both are supplied, it's assumed
     * the public key already correctly matches the public key. if only the public key is supplied, this eckey cannot
     * be used for signing.
     */
    private eckey(biginteger privkey, byte[] pubkey) {
        this.priv = privkey;
        this.pub = null;
        if (pubkey == null && privkey != null) {
            // derive public from private.
            this.pub = publickeyfromprivate(privkey);
        } else if (pubkey != null) {
            // we expect the pubkey to be in regular encoded form, just as a biginteger. therefore the first byte is
            // a special marker byte.
            // todo: this is probably not a useful api and may be confusing.
            this.pub = pubkey;
        }
    }

    /** creates an eckey given the private key only.  the public key is calculated from it (this is slow) */
    public eckey(biginteger privkey) {
        this(privkey, (byte[])null);
    }

    /** a constructor variant with biginteger pubkey. see {@link eckey#eckey(java.math.biginteger, byte[])}. */
    public eckey(biginteger privkey, biginteger pubkey) {
        this(privkey, bitutil.bigintegertobytes(pubkey, 65));
    }

    /**
     * creates an eckey given only the private key bytes. this is the same as using the biginteger constructor, but
     * is more convenient if you are importing a key from elsewhere. the public key will be automatically derived
     * from the private key. .
     */
    public eckey(byte[] privkeybytes, byte[] pubkey) {
        this(privkeybytes == null ? null : new biginteger(1, privkeybytes), pubkey);
    }

    /**
     * create an eckey given the private key in some format string. like btc-qt, base58,
     *
     * @param privstr   all types of private key string
     */
    public static eckey getecfromprivstr(string privstr) throws moorecoinexception {
        if(privstr == null || privstr.length() < 32) throw new moorecoinexception("wrong private key : " + privstr);
        byte[] priv;
        int len = privstr.length();
        if(len == 44 && privstr.endswith("=")) {//maybe base64
            priv = base64.decode(privstr);
        } else if(len == 43 || len == 44) {    //maybe base58
            priv = base58.decode(privstr);
        } else if(privstr.startswith("5") && (len == 51 || len == 52)) { //maybe btc-qt
            byte[] src = base58.decode(privstr);
            if(src.length != 37 || src[0] != (byte)0x80)
                throw new moorecoinexception("wrong private key of btc-qt format: " + bytestohexstring(src));
            priv = new byte[32];
            system.arraycopy(src, 1, priv, 0, 32);
        } else if(len == 64) {          //maybe hex
            priv = parseashexorbase58(privstr);
        } else {
            throw new moorecoinexception("unknown private key format: " + privstr);
        }
        return new eckey(priv, null);
    }

    /**
     * returns public key bytes from the given private key. to convert a byte array into a biginteger, use <tt>
     * new biginteger(1, bytes);</tt>
     */
    public static byte[] publickeyfromprivate(biginteger privkey) {
        return ecparams.getg().multiply(privkey).getencoded();
    }

    /** gets the hash160 form of the public key (as seen in addresses). */
    public byte[] getpubkeyhash() {
        if (pubkeyhash == null)
            pubkeyhash = bitutil.sha256hash160(this.pub);
        return pubkeyhash;
    }

    /**
     * gets the raw public key value. this appears in transaction scriptsigs. note that this is <b>not</b> the same
     * as the pubkeyhash/address.
     */
    public byte[] getpubkey() {
        return pub;
    }

    public string tostring() {
        stringbuffer b = new stringbuffer();
        b.append("pub:").append(bytestohexstring(pub));
        if (creationtimeseconds != 0) {
            b.append(" timestamp:" + creationtimeseconds);
        }
        return b.tostring();
    }

    public string tostringwithprivate() {
        stringbuffer b = new stringbuffer();
        b.append(tostring());
        if (priv != null) {
            b.append(" priv:").append(bytestohexstring(priv.tobytearray()));
        }
        return b.tostring();
    }

    /**
     * returns the address that corresponds to the public part of this eckey. note that an address is derived from
     * the ripemd-160 hash of the public key and is not the public key itself (which is too large to be convenient).
     */
    public address toaddress(int ver) {
        byte[] hash160 = bitutil.sha256hash160(pub);
        return new address(ver, hash160);
    }

    /**
     * calcuates an ecdsa signature in der format for the given input hash. note that the input is expected to be
     * 32 bytes long.
     * @throws illegalstateexception if this eckey has only a public key.
     */
    public byte[] sign(byte[] input) {
        if (priv == null)
            throw new illegalstateexception("this eckey does not have the private key necessary for signing.");
        ecdsasigner signer = new ecdsasigner();
        ecprivatekeyparameters privkey = new ecprivatekeyparameters(priv, ecparams);
        signer.init(true, privkey);
        biginteger[] sigs = signer.generatesignature(input);
        // what we get back from the signer are the two components of a signature, r and s. to get a flat byte stream
        // of the type used by bitcoin we have to encode them using der encoding, which is just a way to pack the two
        // components into a structure.
        try {
            // usually 70-72 bytes.
            bytearrayoutputstream bos = new unsafebytearrayoutputstream(72);
            dersequencegenerator seq = new dersequencegenerator(bos);
            seq.addobject(new derinteger(sigs[0]));
            seq.addobject(new derinteger(sigs[1]));
            seq.close();
            return bos.tobytearray();
        } catch (ioexception e) {
            throw new runtimeexception(e);  // cannot happen.
        }
    }

    /**
     * verifies the given asn.1 encoded ecdsa signature against a hash using the public key.
     *
     * @param data      hash of the data to verify.
     * @param signature asn.1 encoded signature.
     * @param pub       the public key bytes to use.
     */
    public static boolean verify(byte[] data, byte[] signature, byte[] pub) {
        ecdsasigner signer = new ecdsasigner();
        ecpublickeyparameters params = new ecpublickeyparameters(ecparams.getcurve().decodepoint(pub), ecparams);
        signer.init(false, params);
        try {
            asn1inputstream decoder = new asn1inputstream(signature);
            dersequence seq = (dersequence) decoder.readobject();
            derinteger r = (derinteger) seq.getobjectat(0);
            derinteger s = (derinteger) seq.getobjectat(1);
            decoder.close();
            return signer.verifysignature(data, r.getvalue(), s.getvalue());
        } catch (ioexception e) {
            throw new runtimeexception(e);
        }
    }

    /**
     * verifies the given asn.1 encoded ecdsa signature against a hash using the public key.
     *
     * @param data      hash of the data to verify.
     * @param signature asn.1 encoded signature.
     */
    public boolean verify(byte[] data, byte[] signature) {
        return eckey.verify(data, signature, pub);
    }


    private static biginteger extractprivatekeyfromasn1(byte[] asn1privkey) {
        // to understand this code, see the definition of the asn.1 format for ec private keys in the openssl source
        // code in ec_asn1.c:
        //
        // asn1_sequence(ec_privatekey) = {
        //   asn1_simple(ec_privatekey, version, long),
        //   asn1_simple(ec_privatekey, privatekey, asn1_octet_string),
        //   asn1_exp_opt(ec_privatekey, parameters, ecpkparameters, 0),
        //   asn1_exp_opt(ec_privatekey, publickey, asn1_bit_string, 1)
        // } asn1_sequence_end(ec_privatekey)
        //
        try {
            asn1inputstream decoder = new asn1inputstream(asn1privkey);
            dersequence seq = (dersequence) decoder.readobject();
            assert seq.size() == 4 : "input does not appear to be an asn.1 openssl ec private key";
            assert ((derinteger) seq.getobjectat(0)).getvalue().equals(biginteger.one) : "input is of wrong version";
            deroctetstring key = (deroctetstring) seq.getobjectat(1);
            decoder.close();
            return new biginteger(key.getoctets());
        } catch (ioexception e) {
            throw new runtimeexception(e);  // cannot happen, reading from memory stream.
        }
    }

    /**
     * returns a 32 byte array containing the private key.
     */
    public byte[] getprivkeybytes() {
        return bitutil.bigintegertobytes(priv, 32);
    }

    /**
     * exports the private key in the form used by the satoshi com.moorecoin.client "dumpprivkey" and "importprivkey" commands. use
     * the {@link dumpedprivatekey#tostring()} method to get the string.
     *
     * @param ver the network this key is intended for use on.
     * @return private key bytes as a {@link dumpedprivatekey}.
     */
    public dumpedprivatekey getprivatekeyencoded(int ver) {
        return new dumpedprivatekey(ver, getprivkeybytes());
    }

    /**
     * returns the creation time of this key or zero if the key was deserialized from a version that did not store
     * that data.
     */
    public long getcreationtimeseconds() {
        return creationtimeseconds;
    }

    /**
     * sets the creation time of this key. zero is a convention to mean "unavailable". this method can be useful when
     * you have a raw key you are importing from somewhere else.
     * @param newcreationtimeseconds
     */
    public void setcreationtimeseconds(long newcreationtimeseconds) {
        if (newcreationtimeseconds < 0)
            throw new illegalargumentexception("cannot set creation time to negative value: " + newcreationtimeseconds);
        creationtimeseconds = newcreationtimeseconds;
    }


}