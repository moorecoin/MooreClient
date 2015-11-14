package org.ripple.bouncycastle.pqc.jcajce.provider.mceliece;

import java.io.ioexception;
import java.security.publickey;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.dernull;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;
import org.ripple.bouncycastle.asn1.x509.subjectpublickeyinfo;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.pqc.asn1.mceliecepublickey;
import org.ripple.bouncycastle.pqc.crypto.mceliece.mceliecekeypairgenerator;
import org.ripple.bouncycastle.pqc.crypto.mceliece.mcelieceparameters;
import org.ripple.bouncycastle.pqc.crypto.mceliece.mceliecepublickeyparameters;
import org.ripple.bouncycastle.pqc.jcajce.spec.mceliecepublickeyspec;
import org.ripple.bouncycastle.pqc.math.linearalgebra.gf2matrix;

/**
 * this class implements a mceliece public key and is usually instantiated by
 * the {@link mceliecekeypairgenerator} or {@link mceliecekeyfactoryspi}.
 */
public class bcmceliecepublickey
    implements cipherparameters, publickey
{

    /**
     *
     */
    private static final long serialversionuid = 1l;

    // the oid of the algorithm
    private string oid;

    /**
     * the length of the code
     */
    private int n;

    /**
     * the error correction capability of the code
     */
    private int t;

    /**
     * the generator matrix
     */
    private gf2matrix g;

    private mcelieceparameters mcelieceparams;

    /**
     * constructor (used by the {@link mceliecekeypairgenerator}).
     *
     * @param oid
     * @param n   the length of the code
     * @param t   the error correction capability of the code
     * @param g   the generator matrix
     */
    public bcmceliecepublickey(string oid, int n, int t, gf2matrix g)
    {
        this.oid = oid;
        this.n = n;
        this.t = t;
        this.g = g;
    }

    /**
     * constructor (used by the {@link mceliecekeyfactoryspi}).
     *
     * @param keyspec a {@link mceliecepublickeyspec}
     */
    public bcmceliecepublickey(mceliecepublickeyspec keyspec)
    {
        this(keyspec.getoidstring(), keyspec.getn(), keyspec.gett(), keyspec.getg());
    }

    public bcmceliecepublickey(mceliecepublickeyparameters params)
    {
        this(params.getoidstring(), params.getn(), params.gett(), params.getg());
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
        return g.getnumrows();
    }

    /**
     * @return the error correction capability of the code
     */
    public int gett()
    {
        return t;
    }

    /**
     * @return the generator matrix
     */
    public gf2matrix getg()
    {
        return g;
    }

    /**
     * @return a human readable form of the key
     */
    public string tostring()
    {
        string result = "mceliecepublickey:\n";
        result += " length of the code         : " + n + "\n";
        result += " error correction capability: " + t + "\n";
        result += " generator matrix           : " + g.tostring();
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
        if (!(other instanceof bcmceliecepublickey))
        {
            return false;
        }
        bcmceliecepublickey otherkey = (bcmceliecepublickey)other;

        return (n == otherkey.n) && (t == otherkey.t) && g.equals(otherkey.g);
    }

    /**
     * @return the hash code of this key
     */
    public int hashcode()
    {
        return n + t + g.hashcode();
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
     * return the keydata to encode in the subjectpublickeyinfo structure.
     * <p/>
     * the asn.1 definition of the key structure is
     * <p/>
     * <pre>
     *       mceliecepublickey ::= sequence {
     *         n           integer      -- length of the code
     *         t           integer      -- error correcting capability
     *         matrixg     octetstring  -- generator matrix as octet string
     *       }
     * </pre>
     *
     * @return the keydata to encode in the subjectpublickeyinfo structure
     */
    public byte[] getencoded()
    {
        mceliecepublickey key = new mceliecepublickey(new asn1objectidentifier(oid), n, t, g);
        algorithmidentifier algorithmidentifier = new algorithmidentifier(this.getoid(), dernull.instance);

        try
        {
            subjectpublickeyinfo subjectpublickeyinfo = new subjectpublickeyinfo(algorithmidentifier, key);

            return subjectpublickeyinfo.getencoded();
        }
        catch (ioexception e)
        {
            return null;
        }
    }

    public string getformat()
    {
        return null;
    }

    public mcelieceparameters getmcelieceparameters()
    {
        return mcelieceparams;
    }
}
