package org.ripple.bouncycastle.crypto.agreement.jpake;

import java.math.biginteger;
import java.security.securerandom;

import org.ripple.bouncycastle.crypto.cryptoexception;
import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.crypto.mac;
import org.ripple.bouncycastle.crypto.macs.hmac;
import org.ripple.bouncycastle.crypto.params.keyparameter;
import org.ripple.bouncycastle.util.arrays;
import org.ripple.bouncycastle.util.bigintegers;
import org.ripple.bouncycastle.util.strings;

/**
 * primitives needed for a j-pake exchange.
 * <p/>
 * <p/>
 * the recommended way to perform a j-pake exchange is by using
 * two {@link jpakeparticipant}s.  internally, those participants
 * call these primitive operations in {@link jpakeutil}.
 * <p/>
 * <p/>
 * the primitives, however, can be used without a {@link jpakeparticipant}
 * if needed.
 */
public class jpakeutil
{
    static final biginteger zero = biginteger.valueof(0);
    static final biginteger one = biginteger.valueof(1);

    /**
     * return a value that can be used as x1 or x3 during round 1.
     * <p/>
     * <p/>
     * the returned value is a random value in the range <tt>[0, q-1]</tt>.
     */
    public static biginteger generatex1(
        biginteger q,
        securerandom random)
    {
        biginteger min = zero;
        biginteger max = q.subtract(one);
        return bigintegers.createrandominrange(min, max, random);
    }

    /**
     * return a value that can be used as x2 or x4 during round 1.
     * <p/>
     * <p/>
     * the returned value is a random value in the range <tt>[1, q-1]</tt>.
     */
    public static biginteger generatex2(
        biginteger q,
        securerandom random)
    {
        biginteger min = one;
        biginteger max = q.subtract(one);
        return bigintegers.createrandominrange(min, max, random);
    }

    /**
     * converts the given password to a {@link biginteger}
     * for use in arithmetic calculations.
     */
    public static biginteger calculates(char[] password)
    {
        return new biginteger(strings.toutf8bytearray(password));
    }

    /**
     * calculate g^x mod p as done in round 1.
     */
    public static biginteger calculategx(
        biginteger p,
        biginteger g,
        biginteger x)
    {
        return g.modpow(x, p);
    }


    /**
     * calculate ga as done in round 2.
     */
    public static biginteger calculatega(
        biginteger p,
        biginteger gx1,
        biginteger gx3,
        biginteger gx4)
    {
        // ga = g^(x1+x3+x4) = g^x1 * g^x3 * g^x4 
        return gx1.multiply(gx3).multiply(gx4).mod(p);
    }


    /**
     * calculate x2 * s as done in round 2.
     */
    public static biginteger calculatex2s(
        biginteger q,
        biginteger x2,
        biginteger s)
    {
        return x2.multiply(s).mod(q);
    }


    /**
     * calculate a as done in round 2.
     */
    public static biginteger calculatea(
        biginteger p,
        biginteger q,
        biginteger ga,
        biginteger x2s)
    {
        // a = ga^(x*s)
        return ga.modpow(x2s, p);
    }

    /**
     * calculate a zero knowledge proof of x using schnorr's signature.
     * the returned array has two elements {g^v, r = v-x*h} for x.
     */
    public static biginteger[] calculatezeroknowledgeproof(
        biginteger p,
        biginteger q,
        biginteger g,
        biginteger gx,
        biginteger x,
        string participantid,
        digest digest,
        securerandom random)
    {
        biginteger[] zeroknowledgeproof = new biginteger[2];

        /* generate a random v, and compute g^v */
        biginteger vmin = zero;
        biginteger vmax = q.subtract(one);
        biginteger v = bigintegers.createrandominrange(vmin, vmax, random);

        biginteger gv = g.modpow(v, p);
        biginteger h = calculatehashforzeroknowledgeproof(g, gv, gx, participantid, digest); // h

        zeroknowledgeproof[0] = gv;
        zeroknowledgeproof[1] = v.subtract(x.multiply(h)).mod(q); // r = v-x*h

        return zeroknowledgeproof;
    }

    private static biginteger calculatehashforzeroknowledgeproof(
        biginteger g,
        biginteger gr,
        biginteger gx,
        string participantid,
        digest digest)
    {
        digest.reset();

        updatedigestincludingsize(digest, g);

        updatedigestincludingsize(digest, gr);

        updatedigestincludingsize(digest, gx);

        updatedigestincludingsize(digest, participantid);

        byte[] output = new byte[digest.getdigestsize()];
        digest.dofinal(output, 0);

        return new biginteger(output);
    }

    /**
     * validates that g^x4 is not 1.
     *
     * @throws cryptoexception if g^x4 is 1
     */
    public static void validategx4(biginteger gx4)
        throws cryptoexception
    {
        if (gx4.equals(one))
        {
            throw new cryptoexception("g^x validation failed.  g^x should not be 1.");
        }
    }

    /**
     * validates that ga is not 1.
     * <p/>
     * <p/>
     * as described by feng hao...
     * <p/>
     * <blockquote>
     * alice could simply check ga != 1 to ensure it is a generator.
     * in fact, as we will explain in section 3, (x1 + x3 + x4 ) is random over zq even in the face of active attacks.
     * hence, the probability for ga = 1 is extremely small - on the order of 2^160 for 160-bit q.
     * </blockquote>
     *
     * @throws cryptoexception if ga is 1
     */
    public static void validatega(biginteger ga)
        throws cryptoexception
    {
        if (ga.equals(one))
        {
            throw new cryptoexception("ga is equal to 1.  it should not be.  the chances of this happening are on the order of 2^160 for a 160-bit q.  try again.");
        }
    }

    /**
     * validates the zero knowledge proof (generated by
     * {@link #calculatezeroknowledgeproof(biginteger, biginteger, biginteger, biginteger, biginteger, string, digest, securerandom)})
     * is correct.
     *
     * @throws cryptoexception if the zero knowledge proof is not correct
     */
    public static void validatezeroknowledgeproof(
        biginteger p,
        biginteger q,
        biginteger g,
        biginteger gx,
        biginteger[] zeroknowledgeproof,
        string participantid,
        digest digest)
        throws cryptoexception
    {

        /* sig={g^v,r} */
        biginteger gv = zeroknowledgeproof[0];
        biginteger r = zeroknowledgeproof[1];

        biginteger h = calculatehashforzeroknowledgeproof(g, gv, gx, participantid, digest);
        if (!(gx.compareto(zero) == 1 && // g^x > 0
            gx.compareto(p) == -1 && // g^x < p
            gx.modpow(q, p).compareto(one) == 0 && // g^x^q mod q = 1
                /*
                 * below, i took an straightforward way to compute g^r * g^x^h,
                 * which needs 2 exp. using a simultaneous computation technique
                 * would only need 1 exp.
                 */
            g.modpow(r, p).multiply(gx.modpow(h, p)).mod(p).compareto(gv) == 0)) // g^v=g^r * g^x^h
        {
            throw new cryptoexception("zero-knowledge proof validation failed");
        }
    }

    /**
     * calculates the keying material, which can be done after round 2 has completed.
     * a session key must be derived from this key material using a secure key derivation function (kdf).
     * the kdf used to derive the key is handled externally (i.e. not by {@link jpakeparticipant}).
     * <p/>
     * <p/>
     * <pre>
     * keyingmaterial = (b/g^{x2*x4*s})^x2
     * </pre>
     */
    public static biginteger calculatekeyingmaterial(
        biginteger p,
        biginteger q,
        biginteger gx4,
        biginteger x2,
        biginteger s,
        biginteger b)
    {
        return gx4.modpow(x2.multiply(s).negate().mod(q), p).multiply(b).modpow(x2, p);
    }

    /**
     * validates that the given participant ids are not equal.
     * (for the j-pake exchange, each participant must use a unique id.)
     *
     * @throws cryptoexception if the participantid strings are equal.
     */
    public static void validateparticipantidsdiffer(string participantid1, string participantid2)
        throws cryptoexception
    {
        if (participantid1.equals(participantid2))
        {
            throw new cryptoexception(
                "both participants are using the same participantid ("
                    + participantid1
                    + "). this is not allowed. "
                    + "each participant must use a unique participantid.");
        }
    }

    /**
     * validates that the given participant ids are equal.
     * this is used to ensure that the payloads received from
     * each round all come from the same participant.
     *
     * @throws cryptoexception if the participantid strings are equal.
     */
    public static void validateparticipantidsequal(string expectedparticipantid, string actualparticipantid)
        throws cryptoexception
    {
        if (!expectedparticipantid.equals(actualparticipantid))
        {
            throw new cryptoexception(
                "received payload from incorrect partner ("
                    + actualparticipantid
                    + "). expected to receive payload from "
                    + expectedparticipantid
                    + ".");
        }
    }

    /**
     * validates that the given object is not null.
     *
     *  @param object object in question
     * @param description name of the object (to be used in exception message)
     * @throws nullpointerexception if the object is null.
     */
    public static void validatenotnull(object object, string description)
    {
        if (object == null)
        {
            throw new nullpointerexception(description + " must not be null");
        }
    }

    /**
     * calculates the mactag (to be used for key confirmation), as defined by
     * <a href="http://csrc.nist.gov/publications/nistpubs/800-56a/sp800-56a_revision1_mar08-2007.pdf">nist sp 800-56a revision 1</a>,
     * section 8.2 unilateral key confirmation for key agreement schemes.
     * <p/>
     * <p/>
     * <pre>
     * mactag = hmac(mackey, maclen, macdata)
     *
     * mackey = h(k || "jpake_kc")
     *
     * macdata = "kc_1_u" || participantid || partnerparticipantid || gx1 || gx2 || gx3 || gx4
     *
     * note that both participants use "kc_1_u" because the sender of the round 3 message
     * is always the initiator for key confirmation.
     *
     * hmac = {@link hmac} used with the given {@link digest}
     * h = the given {@link digest}</li>
     * maclen = length of mactag
     * </pre>
     * <p/>
     */
    public static biginteger calculatemactag(
        string participantid,
        string partnerparticipantid,
        biginteger gx1,
        biginteger gx2,
        biginteger gx3,
        biginteger gx4,
        biginteger keyingmaterial,
        digest digest)
    {
        byte[] mackey = calculatemackey(
            keyingmaterial,
            digest);

        hmac mac = new hmac(digest);
        byte[] macoutput = new byte[mac.getmacsize()];
        mac.init(new keyparameter(mackey));
        
        /*
         * macdata = "kc_1_u" || participantid_alice || participantid_bob || gx1 || gx2 || gx3 || gx4.
         */
        updatemac(mac, "kc_1_u");
        updatemac(mac, participantid);
        updatemac(mac, partnerparticipantid);
        updatemac(mac, gx1);
        updatemac(mac, gx2);
        updatemac(mac, gx3);
        updatemac(mac, gx4);

        mac.dofinal(macoutput, 0);

        arrays.fill(mackey, (byte)0);

        return new biginteger(macoutput);

    }

    /**
     * calculates the mackey (i.e. the key to use when calculating the magtag for key confirmation).
     * <p/>
     * <p/>
     * <pre>
     * mackey = h(k || "jpake_kc")
     * </pre>
     */
    private static byte[] calculatemackey(biginteger keyingmaterial, digest digest)
    {
        digest.reset();

        updatedigest(digest, keyingmaterial);
        /*
         * this constant is used to ensure that the mackey is not the same as the derived key.
         */
        updatedigest(digest, "jpake_kc");

        byte[] output = new byte[digest.getdigestsize()];
        digest.dofinal(output, 0);

        return output;
    }

    /**
     * validates the mactag received from the partner participant.
     * <p/>
     *
     * @param partnermactag the mactag received from the partner.
     * @throws cryptoexception if the participantid strings are equal.
     */
    public static void validatemactag(
        string participantid,
        string partnerparticipantid,
        biginteger gx1,
        biginteger gx2,
        biginteger gx3,
        biginteger gx4,
        biginteger keyingmaterial,
        digest digest,
        biginteger partnermactag)
        throws cryptoexception
    {
        /*
         * calculate the expected mactag using the parameters as the partner
         * would have used when the partner called calculatemactag.
         * 
         * i.e. basically all the parameters are reversed.
         * participantid <-> partnerparticipantid
         *            x1 <-> x3
         *            x2 <-> x4
         */
        biginteger expectedmactag = calculatemactag(
            partnerparticipantid,
            participantid,
            gx3,
            gx4,
            gx1,
            gx2,
            keyingmaterial,
            digest);

        if (!expectedmactag.equals(partnermactag))
        {
            throw new cryptoexception(
                "partner mactag validation failed. "
                    + "therefore, the password, mac, or digest algorithm of each participant does not match.");
        }
    }

    private static void updatedigest(digest digest, biginteger biginteger)
    {
        byte[] bytearray = bigintegers.asunsignedbytearray(biginteger);
        digest.update(bytearray, 0, bytearray.length);
        arrays.fill(bytearray, (byte)0);
    }

    private static void updatedigestincludingsize(digest digest, biginteger biginteger)
    {
        byte[] bytearray = bigintegers.asunsignedbytearray(biginteger);
        digest.update(inttobytearray(bytearray.length), 0, 4);
        digest.update(bytearray, 0, bytearray.length);
        arrays.fill(bytearray, (byte)0);
    }

    private static void updatedigest(digest digest, string string)
    {
        byte[] bytearray = strings.toutf8bytearray(string);
        digest.update(bytearray, 0, bytearray.length);
        arrays.fill(bytearray, (byte)0);
    }

    private static void updatedigestincludingsize(digest digest, string string)
    {
        byte[] bytearray = strings.toutf8bytearray(string);
        digest.update(inttobytearray(bytearray.length), 0, 4);
        digest.update(bytearray, 0, bytearray.length);
        arrays.fill(bytearray, (byte)0);
    }

    private static void updatemac(mac mac, biginteger biginteger)
    {
        byte[] bytearray = bigintegers.asunsignedbytearray(biginteger);
        mac.update(bytearray, 0, bytearray.length);
        arrays.fill(bytearray, (byte)0);
    }

    private static void updatemac(mac mac, string string)
    {
        byte[] bytearray = strings.toutf8bytearray(string);
        mac.update(bytearray, 0, bytearray.length);
        arrays.fill(bytearray, (byte)0);
    }

    private static byte[] inttobytearray(int value)
    {
        return new byte[]{
            (byte)(value >>> 24),
            (byte)(value >>> 16),
            (byte)(value >>> 8),
            (byte)value
        };
    }

}
