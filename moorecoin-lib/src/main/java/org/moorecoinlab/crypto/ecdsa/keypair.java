package org.moorecoinlab.crypto.ecdsa;

import org.moorecoinlab.core.utils;
import org.moorecoinlab.core.hash.b58;
import org.ripple.bouncycastle.crypto.params.ecprivatekeyparameters;
import org.ripple.bouncycastle.crypto.params.ecpublickeyparameters;
import org.ripple.bouncycastle.crypto.signers.ecdsasigner;
import org.ripple.bouncycastle.math.ec.ecpoint;

import java.math.biginteger;

public class keypair implements ikeypair {
    biginteger priv, pub;
    byte[] pubbytes;

    @override
    public biginteger pub() {
        return pub;
    }

    @override
    public byte[] pubbytes() {
        return pubbytes;
    }

    @deprecated
    public keypair(biginteger priv, biginteger pub) {
        this.priv = priv;
        this.pub = pub;
        this.pubbytes = pub.tobytearray();
    }

    /**
     * constructor using only private key, for btc convert.
     * @author  fau
     * @since   2014-10-21
     * @param privategenbytes
     */
    public keypair(byte[] privategenbytes) {
        this(utils.ubigint(privategenbytes));
    }
    /**
     * constructor using only private key, for btc convert.
     * @author  fau
     * @since   2014-10-21
     * @param privategen  biginteger
     */
    public keypair(biginteger privategen) {
        biginteger secret, pub, order = secp256k1.order();
        byte[] publicgenbytes;

        int i = 0, seq = 0;
        publicgenbytes = secp256k1.basepointmultipliedby(privategen);
        //system.out.println("keypair() from priv to pub : " + convert.bytestohex(publicgenbytes));

        this.priv = privategen;
        this.pub  = utils.ubigint(publicgenbytes);
        this.pubbytes = publicgenbytes;
    }

    @override
    public biginteger priv() {
        return priv;
    }

    @override
    public boolean verify(byte[] data, byte[] sigbytes) {
        return verify(data, sigbytes, pub);
    }

    @override
    public byte[] sign(byte[] bytes) {
        return sign(bytes, priv);
    }

    @override
    public byte[] sha256_ripemd160_pub() {
        return utils.sha256_ripemd160(pubbytes);
    }

    @override
    public string pubhex() {
        return utils.bighex(pub);
    }

    @override
    public string privhex() {
        string s = utils.bighex(priv);
        if(s.startswith("00") && s.length() == b58.len_private_key * 2 + 2)
            return s.substring(2);
        return s;
    }

    public static boolean verify(byte[] data, byte[] sigbytes, biginteger pub) {
        ecdsasignature signature = ecdsasignature.decodefromder(sigbytes);
        ecdsasigner signer = new ecdsasigner();
        ecpoint pubpoint = secp256k1.curve().decodepoint(pub.tobytearray());
        ecpublickeyparameters params = new ecpublickeyparameters(pubpoint, secp256k1.params());
        signer.init(false, params);
        try {
            return signer.verifysignature(data, signature.r, signature.s);
        } catch (nullpointerexception e) {
            e.printstacktrace();
            return false;
        }
    }
    public static byte[] sign(byte[] bytes, biginteger secret) {
        ecdsasignature sig = createecdsasignature(bytes, secret);
        byte[] der = sig.encodetoder();
        if (!isstrictlycanonical(der)) {
            throw new illegalstateexception("signature is not strictly canonical");
        }
        return der;
    }
    public static boolean isstrictlycanonical(byte[] sig) {
        return checkiscanonical(sig, true);
    }

    public static boolean checkiscanonical(byte[] sig, boolean strict) {
        // make sure signature is canonical
        // to protect against signature morphing attacks

        // signature should be:
        // <30> <len> [ <02> <lenr> <r> ] [ <02> <lens> <s> ]
        // where
        // 6 <= len <= 70
        // 1 <= lenr <= 33
        // 1 <= lens <= 33

        int siglen = sig.length;

        if ((siglen < 8) || (siglen > 72))
            return false;

        if ((sig[0] != 0x30) || (sig[1] != (siglen - 2)))
            return false;

        // find r and check its length
        int rpos = 4, rlen = sig[rpos - 1];

        if ((rlen < 1) || (rlen > 33) || ((rlen + 7) > siglen))
            return false;

        // find s and check its length
        int spos = rlen + 6, slen = sig[spos - 1];
        if ((slen < 1) || (slen > 33) || ((rlen + slen + 6) != siglen))
            return false;

        if ((sig[rpos - 2] != 0x02) || (sig[spos - 2] != 0x02))
            return false; // r or s have wrong type

        if ((sig[rpos] & 0x80) != 0)
            return false; // r is negative

        if ((sig[rpos] == 0) && rlen == 1)
            return false; // r is zero

        if ((sig[rpos] == 0) && ((sig[rpos + 1] & 0x80) == 0))
            return false; // r is padded

        if ((sig[spos] & 0x80) != 0)
            return false; // s is negative

        if ((sig[spos] == 0) && slen == 1)
            return false; // s is zero

        if ((sig[spos] == 0) && ((sig[spos + 1] & 0x80) == 0))
            return false; // s is padded


        byte[] rbytes = new byte[rlen];
        byte[] sbytes = new byte[slen];

        system.arraycopy(sig, rpos, rbytes, 0, rlen);
        system.arraycopy(sig, spos, sbytes, 0, slen);

        biginteger r = new biginteger(1, rbytes), s = new biginteger(1, sbytes);

        biginteger order = secp256k1.order();

        if (r.compareto(order) != -1 || s.compareto(order) != -1) {
            return false; // r or s greater than modulus
        }
        if (strict) {
            return order.subtract(s).compareto(s) != -1;
        } else {
            return true;
        }

    }

    private static ecdsasignature createecdsasignature(byte[] bytes, biginteger secret) {
        ecdsasigner signer = new ecdsasigner();
        ecprivatekeyparameters privkey = new ecprivatekeyparameters(secret, secp256k1.params());
        signer.init(true, privkey);
        biginteger[] sigs = signer.generatesignature(bytes);
        biginteger r = sigs[0], s = sigs[1];

        biginteger others = secp256k1.order().subtract(s);
        if (s.compareto(others) == 1) {
            s = others;
        }

        return new ecdsasignature(r, s);
    }
}
