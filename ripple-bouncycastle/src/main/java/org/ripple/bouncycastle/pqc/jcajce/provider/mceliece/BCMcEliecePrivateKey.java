package org.ripple.bouncycastle.pqc.jcajce.provider.mceliece;

import java.io.ioexception;
import java.security.privatekey;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.dernull;
import org.ripple.bouncycastle.asn1.pkcs.privatekeyinfo;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.pqc.asn1.mcelieceprivatekey;
import org.ripple.bouncycastle.pqc.crypto.mceliece.mceliecekeypairgenerator;
import org.ripple.bouncycastle.pqc.crypto.mceliece.mcelieceparameters;
import org.ripple.bouncycastle.pqc.crypto.mceliece.mcelieceprivatekeyparameters;
import org.ripple.bouncycastle.pqc.jcajce.spec.mcelieceprivatekeyspec;
import org.ripple.bouncycastle.pqc.math.linearalgebra.gf2matrix;
import org.ripple.bouncycastle.pqc.math.linearalgebra.gf2mfield;
import org.ripple.bouncycastle.pqc.math.linearalgebra.permutation;
import org.ripple.bouncycastle.pqc.math.linearalgebra.polynomialgf2msmallm;

/**
 * this class implements a mceliece private key and is usually instantiated by
 * the {@link mceliecekeypairgenerator} or {@link mceliecekeyfactoryspi}.
 */
public class bcmcelieceprivatekey
    implements cipherparameters, privatekey
{

    /**
     *
     */
    private static final long serialversionuid = 1l;

    // the oid of the algorithm
    private string oid;

    // the length of the code
    private int n;

    // the dimension of the code, where <tt>k &gt;= n - mt</tt>
    private int k;

    // the underlying finite field
    private gf2mfield field;

    // the irreducible goppa polynomial
    private polynomialgf2msmallm goppapoly;

    // the matrix s^-1
    private gf2matrix sinv;

    // the permutation p1 used to generate the systematic check matrix
    private permutation p1;

    // the permutation p2 used to compute the public generator matrix
    private permutation p2;

    // the canonical check matrix of the code
    private gf2matrix h;

    // the matrix used to compute square roots in <tt>(gf(2^m))^t</tt>
    private polynomialgf2msmallm[] qinv;

    private mcelieceparameters mcelieceparams;


    /**
     * constructor (used by the {@link mceliecekeypairgenerator}).
     *
     * @param oid
     * @param n         the length of the code
     * @param k         the dimension of the code
     * @param field     the field polynomial defining the finite field
     *                  <tt>gf(2<sup>m</sup>)</tt>
     * @param goppapoly the irreducible goppa polynomial
     * @param sinv      the matrix <tt>s<sup>-1</sup></tt>
     * @param p1        the permutation used to generate the systematic check
     *                  matrix
     * @param p2        the permutation used to compute the public generator
     *                  matrix
     * @param h         the canonical check matrix
     * @param qinv      the matrix used to compute square roots in
     *                  <tt>(gf(2<sup>m</sup>))<sup>t</sup></tt>
     */
    public bcmcelieceprivatekey(string oid, int n, int k, gf2mfield field,
                                polynomialgf2msmallm goppapoly, gf2matrix sinv, permutation p1,
                                permutation p2, gf2matrix h, polynomialgf2msmallm[] qinv)
    {
        this.oid = oid;
        this.n = n;
        this.k = k;
        this.field = field;
        this.goppapoly = goppapoly;
        this.sinv = sinv;
        this.p1 = p1;
        this.p2 = p2;
        this.h = h;
        this.qinv = qinv;
    }

    /**
     * constructor (used by the {@link mceliecekeyfactoryspi}).
     *
     * @param keyspec a {@link mcelieceprivatekeyspec}
     */
    public bcmcelieceprivatekey(mcelieceprivatekeyspec keyspec)
    {
        this(keyspec.getoidstring(), keyspec.getn(), keyspec.getk(), keyspec.getfield(), keyspec
            .getgoppapoly(), keyspec.getsinv(), keyspec.getp1(), keyspec
            .getp2(), keyspec.geth(), keyspec.getqinv());
    }

    public bcmcelieceprivatekey(mcelieceprivatekeyparameters params)
    {
        this(params.getoidstring(), params.getn(), params.getk(), params.getfield(), params.getgoppapoly(),
            params.getsinv(), params.getp1(), params.getp2(), params.geth(), params.getqinv());

        this.mcelieceparams = params.getparameters();
    }


    /**
     * return the name of the algorithm.
     *
     * @return "mceliece"
     */
    public string getalgorithm()
    {
        return "mceliece";
    }

    /**
     * @return the length of the code
     */
    public int getn()
    {
        return n;
    }

    /**
     * @return the dimension of the code
     */
    public int getk()
    {
        return k;
    }

    /**
     * @return the finite field
     */
    public gf2mfield getfield()
    {
        return field;
    }

    /**
     * @return the irreducible goppa polynomial
     */
    public polynomialgf2msmallm getgoppapoly()
    {
        return goppapoly;
    }

    /**
     * @return the k x k random binary non-singular matrix s
     */
    public gf2matrix getsinv()
    {
        return sinv;
    }

    /**
     * @return the permutation used to generate the systematic check matrix
     */
    public permutation getp1()
    {
        return p1;
    }

    /**
     * @return the permutation used to compute the public generator matrix
     */
    public permutation getp2()
    {
        return p2;
    }

    /**
     * @return the canonical check matrix
     */
    public gf2matrix geth()
    {
        return h;
    }

    /**
     * @return the matrix for computing square roots in <tt>(gf(2^m))^t</tt>
     */
    public polynomialgf2msmallm[] getqinv()
    {
        return qinv;
    }

    /**
     * @return the oid of the algorithm
     */
    public string getoidstring()
    {
        return oid;
    }

    /**
     * @return a human readable form of the key
     */
    public string tostring()
    {
        string result = " length of the code          : " + n + "\n";
        result += " dimension of the code       : " + k + "\n";
        result += " irreducible goppa polynomial: " + goppapoly + "\n";
        result += " (k x k)-matrix s^-1         : " + sinv + "\n";
        result += " permutation p1              : " + p1 + "\n";
        result += " permutation p2              : " + p2;
        return result;
    }

    /**
     * compare this key with another object.
     *
     * @param other the other object
     * @return the result of the comparison
     */
    public boolean equals(object other)
    {
        if (!(other instanceof bcmcelieceprivatekey))
        {
            return false;
        }
        bcmcelieceprivatekey otherkey = (bcmcelieceprivatekey)other;

        return (n == otherkey.n) && (k == otherkey.k)
            && field.equals(otherkey.field)
            && goppapoly.equals(otherkey.goppapoly)
            && sinv.equals(otherkey.sinv) && p1.equals(otherkey.p1)
            && p2.equals(otherkey.p2) && h.equals(otherkey.h);
    }

    /**
     * @return the hash code of this key
     */
    public int hashcode()
    {
        return k + n + field.hashcode() + goppapoly.hashcode()
            + sinv.hashcode() + p1.hashcode() + p2.hashcode()
            + h.hashcode();
    }

    /**
     * @return the oid to encode in the subjectpublickeyinfo structure
     */
    protected asn1objectidentifier getoid()
    {
        return new asn1objectidentifier(mceliecekeyfactoryspi.oid);
    }

    /**
     * @return the algorithm parameters to encode in the subjectpublickeyinfo
     *         structure
     */
    protected asn1primitive getalgparams()
    {
        return null; // fixme: needed at all?
    }

    /**
     * return the key data to encode in the subjectpublickeyinfo structure.
     * <p/>
     * the asn.1 definition of the key structure is
     * <p/>
     * <pre>
     *   mcelieceprivatekey ::= sequence {
     *     n          integer                   -- length of the code
     *     k          integer                   -- dimension of the code
     *     fieldpoly  octet string              -- field polynomial defining gf(2&circ;m)
     *     goppapoly  octet string              -- irreducible goppa polynomial
     *     sinv       octet string              -- matrix s&circ;-1
     *     p1         octet string              -- permutation p1
     *     p2         octet string              -- permutation p2
     *     h          octet string              -- canonical check matrix
     *     qinv       sequence of octet string  -- matrix used to compute square roots
     *   }
     * </pre>
     *
     * @return the key data to encode in the subjectpublickeyinfo structure
     */
    public byte[] getencoded()
    {
        mcelieceprivatekey privatekey = new mcelieceprivatekey(new asn1objectidentifier(oid), n, k, field, goppapoly, sinv, p1, p2, h, qinv);
        privatekeyinfo pki;
        try
        {
            algorithmidentifier algorithmidentifier = new algorithmidentifier(this.getoid(), dernull.instance);
            pki = new privatekeyinfo(algorithmidentifier, privatekey);
        }
        catch (ioexception e)
        {
            e.printstacktrace();
            return null;
        }
        try
        {
            byte[] encoded = pki.getencoded();
            return encoded;
        }
        catch (ioexception e)
        {
            e.printstacktrace();
            return null;
        }
    }

    public string getformat()
    {
        // todo auto-generated method stub
        return null;
    }

    public mcelieceparameters getmcelieceparameters()
    {
        return mcelieceparams;
    }


}
