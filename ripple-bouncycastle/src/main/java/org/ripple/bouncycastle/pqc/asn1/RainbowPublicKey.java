package org.ripple.bouncycastle.pqc.asn1;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.deroctetstring;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.pqc.crypto.rainbow.util.rainbowutil;

/**
 * this class implements an asn.1 encoded rainbow public key. the asn.1 definition
 * of this structure is:
 * <p/>
 * <pre>
 *       rainbowpublickey ::= sequence {
 *         choice
 *         {
 *         oid        object identifier         -- oid identifying the algorithm
 *         version    integer                    -- 0
 *         }
 *         doclength        integer               -- length of the code
 *         coeffquadratic   sequence of octet string -- quadratic (mixed) coefficients
 *         coeffsingular    sequence of octet string -- singular coefficients
 *         coeffscalar    sequence of octet string -- scalar coefficients
 *       }
 * </pre>
 */
public class rainbowpublickey
    extends asn1object
{
    private asn1integer version;
    private asn1objectidentifier oid;
    private asn1integer doclength;
    private byte[][] coeffquadratic;
    private byte[][] coeffsingular;
    private byte[] coeffscalar;

    private rainbowpublickey(asn1sequence seq)
    {
        // <oidstring>  or version
        if (seq.getobjectat(0) instanceof asn1integer)
        {
            version = asn1integer.getinstance(seq.getobjectat(0));
        }
        else
        {
            oid = asn1objectidentifier.getinstance(seq.getobjectat(0));
        }

        doclength = asn1integer.getinstance(seq.getobjectat(1));

        asn1sequence asncoeffquad = asn1sequence.getinstance(seq.getobjectat(2));
        coeffquadratic = new byte[asncoeffquad.size()][];
        for (int quadsize = 0; quadsize < asncoeffquad.size(); quadsize++)
        {
            coeffquadratic[quadsize] = asn1octetstring.getinstance(asncoeffquad.getobjectat(quadsize)).getoctets();
        }

        asn1sequence asncoeffsing = (asn1sequence)seq.getobjectat(3);
        coeffsingular = new byte[asncoeffsing.size()][];
        for (int singsize = 0; singsize < asncoeffsing.size(); singsize++)
        {
            coeffsingular[singsize] = asn1octetstring.getinstance(asncoeffsing.getobjectat(singsize)).getoctets();
        }

        asn1sequence asncoeffscalar = (asn1sequence)seq.getobjectat(4);
        coeffscalar = asn1octetstring.getinstance(asncoeffscalar.getobjectat(0)).getoctets();
    }

    public rainbowpublickey(int doclength, short[][] coeffquadratic, short[][] coeffsingular, short[] coeffscalar)
    {
        this.version = new asn1integer(0);
        this.doclength = new asn1integer(doclength);
        this.coeffquadratic = rainbowutil.convertarray(coeffquadratic);
        this.coeffsingular = rainbowutil.convertarray(coeffsingular);
        this.coeffscalar = rainbowutil.convertarray(coeffscalar);
    }

    public static rainbowpublickey getinstance(object o)
    {
        if (o instanceof rainbowpublickey)
        {
            return (rainbowpublickey)o;
        }
        else if (o != null)
        {
            return new rainbowpublickey(asn1sequence.getinstance(o));
        }

        return null;
    }

    public asn1integer getversion()
    {
        return version;
    }

    /**
     * @return the doclength
     */
    public int getdoclength()
    {
        return this.doclength.getvalue().intvalue();
    }

    /**
     * @return the coeffquadratic
     */
    public short[][] getcoeffquadratic()
    {
        return rainbowutil.convertarray(coeffquadratic);
    }

    /**
     * @return the coeffsingular
     */
    public short[][] getcoeffsingular()
    {
        return rainbowutil.convertarray(coeffsingular);
    }

    /**
     * @return the coeffscalar
     */
    public short[] getcoeffscalar()
    {
        return rainbowutil.convertarray(coeffscalar);
    }

    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        // encode <oidstring>  or version
        if (version != null)
        {
            v.add(version);
        }
        else
        {
            v.add(oid);
        }

        // encode <doclength>
        v.add(doclength);

        // encode <coeffquadratic>
        asn1encodablevector asncoeffquad = new asn1encodablevector();
        for (int i = 0; i < coeffquadratic.length; i++)
        {
            asncoeffquad.add(new deroctetstring(coeffquadratic[i]));
        }
        v.add(new dersequence(asncoeffquad));

        // encode <coeffsingular>
        asn1encodablevector asncoeffsing = new asn1encodablevector();
        for (int i = 0; i < coeffsingular.length; i++)
        {
            asncoeffsing.add(new deroctetstring(coeffsingular[i]));
        }
        v.add(new dersequence(asncoeffsing));

        // encode <coeffscalar>
        asn1encodablevector asncoeffscalar = new asn1encodablevector();
        asncoeffscalar.add(new deroctetstring(coeffscalar));
        v.add(new dersequence(asncoeffscalar));


        return new dersequence(v);
    }
}
