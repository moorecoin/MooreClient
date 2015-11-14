package org.ripple.bouncycastle.pqc.jcajce.provider.mceliece;

import java.io.ioexception;
import java.security.privatekey;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.dernull;
import org.ripple.bouncycastle.asn1.pkcs.privatekeyinfo;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.pqc.asn1.mceliececca2privatekey;
import org.ripple.bouncycastle.pqc.crypto.mceliece.mceliececca2keypairgenerator;
import org.ripple.bouncycastle.pqc.crypto.mceliece.mceliececca2parameters;
import org.ripple.bouncycastle.pqc.crypto.mceliece.mceliececca2privatekeyparameters;
import org.ripple.bouncycastle.pqc.jcajce.spec.mceliececca2privatekeyspec;
import org.ripple.bouncycastle.pqc.math.linearalgebra.gf2matrix;
import org.ripple.bouncycastle.pqc.math.linearalgebra.gf2mfield;
import org.ripple.bouncycastle.pqc.math.linearalgebra.permutation;
import org.ripple.bouncycastle.pqc.math.linearalgebra.polynomialgf2msmallm;

/**
 * this class implements a mceliece cca2 private key and is usually instantiated
 * by the {@link mceliececca2keypairgenerator} or {@link mceliececca2keyfactoryspi}.
 *
 * @see mceliececca2keypairgenerator
 */
public class bcmceliececca2privatekey
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

    // the dimension of the code, k>=n-mt
    private int k;

    // the finte field gf(2^m)
    private gf2mfield field;

    // the irreducible goppa polynomial
    private polynomialgf2msmallm goppapoly;

    // the permutation
    private permutation p;

    // the canonical check matrix
    private gf2matrix h;

    // the matrix used to compute square roots in (gf(2^m))^t
    private polynomialgf2msmallm[] qinv;

    private mceliececca2parameters mceliececca2params;

    /**
     * constructor (used by the {@link mceliececca2keypairgenerator}).
     *
     * @param n     the length of the code
     * @param k     the dimension of the code
     * @param field the field polynomial
     * @param gp    the irreducible goppa polynomial
     * @param p     the permutation
     * @param h     the canonical check matrix
     * @param qinv  the matrix used to compute square roots in
     *              <tt>(gf(2^m))^t</tt>
     */
    public bcmceliececca2privatekey(string oid, int n, int k, gf2mfield field,
                                    polynomialgf2msmallm gp, permutation p, gf2matrix h,
                                    polynomialgf2msmallm[] qinv)
    {
        this.oid = oid;
        this.n = n;
        this.k = k;
        this.field = field;
        this.goppapoly = gp;
        this.p = p;
        this.h = h;
        this.qinv = qinv;
    }

    /**
     * constructor (used by the {@link mceliececca2keyfactoryspi}).
     *
     * @param keyspec a {@link mceliececca2privatekeyspec}
     */
    public bcmceliececca2privatekey(mceliececca2privatekeyspec keyspec)
    {
        this(keyspec.getoidstring(), keyspec.getn(), keyspec.getk(), keyspec.getfield(), keyspec
            .getgoppapoly(), keyspec.getp(), keyspec.geth(), keyspec
            .getqinv());
    }

    public bcmceliececca2privatekey(mceliececca2privatekeyparameters params)
    {
        this(params.getoidstring(), params.getn(), params.getk(), params.getfield(), params.getgoppapoly(),
            params.getp(), params.geth(), params.getqinv());
        this.mceliececca2params = params.getparameters();
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
     * @return the degree of the goppa polynomial (error correcting capability)
     */
    public int gett()
    {
        return goppapoly.getdegree();
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
     * @return the permutation vector
     */
    public permutation getp()
    {
        return p;
    }

    /**
     * @return the canonical check matrix
     */
    public gf2matrix geth()
    {
        return h;
    }

    /**
     * @return the matrix used to compute square roots in <tt>(gf(2^m))^t</tt>
     */
    public polynomialgf2msmallm[] getqinv()
    {
        return qinv;
    }

    /**
     * @return a human readable form of the key
     */
    public string tostring()
    {
        string result = "";
        result += " extension degree of the field      : " + n + "\n";
        result += " dimension of the code              : " + k + "\n";
        result += " irreducible goppa polynomial       : " + goppapoly + "\n";
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
        if (other == null || !(other instanceof bcmceliececca2privatekey))
        {
            return false;
        }

        bcmceliececca2privatekey otherkey = (bcmceliececca2privatekey)other;

        return (n == otherkey.n) && (k == otherkey.k)
            && field.equals(otherkey.field)
            && goppapoly.equals(otherkey.goppapoly) && p.equals(otherkey.p)
            && h.equals(otherkey.h);
    }

    /**
     * @return the hash code of this key
     */
    public int hashcode()
    {
        return k + n + field.hashcode() + goppapoly.hashcode() + p.hashcode()
            + h.hashcode();
    }

    /**
     * @return the oid of the algorithm
     */
    public string getoidstring()
    {
        return oid;
    }

    /**
     * @return the oid to encode in the subjectpublickeyinfo structure
     */
    protected asn1objectidentifier getoid()
    {
        return new asn1objectidentifier(mceliececca2keyfactoryspi.oid);
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
     * return the keydata to encode in the subjectpublickeyinfo structure.
     * <p/>
     * the asn.1 definition of the key structure is
     * <p/>
     * <pre>
     *   mcelieceprivatekey ::= sequence {
     *     m             integer                  -- extension degree of the field
     *     k             integer                  -- dimension of the code
     *     field         octet string             -- field polynomial
     *     goppapoly     octet string             -- irreducible goppa polynomial
     *     p             octet string             -- permutation vector
     *     matrixh       octet string             -- canonical check matrix
     *     sqrootmatrix  sequence of octet string -- square root matrix
     *   }
     * </pre>
     *
     * @return the keydata to encode in the subjectpublickeyinfo structure
     */
    public byte[] getencoded()
    {
        mceliececca2privatekey privatekey = new mceliececca2privatekey(new asn1objectidentifier(oid), n, k, field, goppapoly, p, h, qinv);
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

    public mceliececca2parameters getmceliececca2parameters()
    {
        return mceliececca2params;
    }

}
