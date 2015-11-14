package org.ripple.bouncycastle.asn1.eac;

import java.math.biginteger;
import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;


/**
 * an iso7816rsapublickeystructure structure.
 * <p/>
 * <pre>
 *  certificate holder authorization ::= sequence {
 *      // modulus should be at least 1024bit and a multiple of 512.
 *      dertaggedobject        modulus,
 *      // access rights    exponent
 *      dertaggedobject    accessrights,
 *  }
 * </pre>
 */
public class rsapublickey
    extends publickeydataobject
{
    private asn1objectidentifier usage;
    private biginteger modulus;
    private biginteger exponent;
    private int valid = 0;
    private static int modulusvalid = 0x01;
    private static int exponentvalid = 0x02;

    rsapublickey(asn1sequence seq)
    {
        enumeration en = seq.getobjects();

        this.usage = asn1objectidentifier.getinstance(en.nextelement());

        while (en.hasmoreelements())
        {
            unsignedinteger val = unsignedinteger.getinstance(en.nextelement());

            switch (val.gettagno())
            {
            case 0x1:
                setmodulus(val);
                break;
            case 0x2:
                setexponent(val);
                break;
            default:
                throw new illegalargumentexception("unknown dertaggedobject :" + val.gettagno() + "-> not an iso7816rsapublickeystructure");
            }
        }
        if (valid != 0x3)
        {
            throw new illegalargumentexception("missing argument -> not an iso7816rsapublickeystructure");
        }
    }

    public rsapublickey(asn1objectidentifier usage, biginteger modulus, biginteger exponent)
    {
        this.usage = usage;
        this.modulus = modulus;
        this.exponent = exponent;
    }

    public asn1objectidentifier getusage()
    {
        return usage;
    }

    public biginteger getmodulus()
    {
        return modulus;
    }

    public biginteger getpublicexponent()
    {
        return exponent;
    }

    private void setmodulus(unsignedinteger modulus)
    {
        if ((valid & modulusvalid) == 0)
        {
            valid |= modulusvalid;
            this.modulus = modulus.getvalue();
        }
        else
        {
            throw new illegalargumentexception("modulus already set");
        }
    }

    private void setexponent(unsignedinteger exponent)
    {
        if ((valid & exponentvalid) == 0)
        {
            valid |= exponentvalid;
            this.exponent = exponent.getvalue();
        }
        else
        {
            throw new illegalargumentexception("exponent already set");
        }
    }

    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        v.add(usage);
        v.add(new unsignedinteger(0x01, getmodulus()));
        v.add(new unsignedinteger(0x02, getpublicexponent()));

        return new dersequence(v);
    }
}
