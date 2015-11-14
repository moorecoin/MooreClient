package org.ripple.bouncycastle.asn1.x9;

import java.math.biginteger;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.derbitstring;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.math.ec.eccurve;

/**
 * asn.1 def for elliptic-curve curve structure. see
 * x9.62, for further details.
 */
public class x9curve
    extends asn1object
    implements x9objectidentifiers
{
    private eccurve     curve;
    private byte[]      seed;
    private asn1objectidentifier fieldidentifier = null;

    public x9curve(
        eccurve     curve)
    {
        this.curve = curve;
        this.seed = null;
        setfieldidentifier();
    }

    public x9curve(
        eccurve     curve,
        byte[]      seed)
    {
        this.curve = curve;
        this.seed = seed;
        setfieldidentifier();
    }

    public x9curve(
        x9fieldid     fieldid,
        asn1sequence  seq)
    {
        fieldidentifier = fieldid.getidentifier();
        if (fieldidentifier.equals(prime_field))
        {
            biginteger      p = ((asn1integer)fieldid.getparameters()).getvalue();
            x9fieldelement  x9a = new x9fieldelement(p, (asn1octetstring)seq.getobjectat(0));
            x9fieldelement  x9b = new x9fieldelement(p, (asn1octetstring)seq.getobjectat(1));
            curve = new eccurve.fp(p, x9a.getvalue().tobiginteger(), x9b.getvalue().tobiginteger());
        }
        else if (fieldidentifier.equals(characteristic_two_field)) 
        {
            // characteristic two field
            asn1sequence parameters = asn1sequence.getinstance(fieldid.getparameters());
            int m = ((asn1integer)parameters.getobjectat(0)).getvalue().
                intvalue();
            asn1objectidentifier representation
                = (asn1objectidentifier)parameters.getobjectat(1);

            int k1 = 0;
            int k2 = 0;
            int k3 = 0;

            if (representation.equals(tpbasis)) 
            {
                // trinomial basis representation
                k1 = asn1integer.getinstance(parameters.getobjectat(2)).getvalue().intvalue();
            }
            else if (representation.equals(ppbasis))
            {
                // pentanomial basis representation
                asn1sequence pentanomial = asn1sequence.getinstance(parameters.getobjectat(2));
                k1 = asn1integer.getinstance(pentanomial.getobjectat(0)).getvalue().intvalue();
                k2 = asn1integer.getinstance(pentanomial.getobjectat(1)).getvalue().intvalue();
                k3 = asn1integer.getinstance(pentanomial.getobjectat(2)).getvalue().intvalue();
            }
            else
            {
                throw new illegalargumentexception("this type of ec basis is not implemented");
            }
            x9fieldelement x9a = new x9fieldelement(m, k1, k2, k3, (asn1octetstring)seq.getobjectat(0));
            x9fieldelement x9b = new x9fieldelement(m, k1, k2, k3, (asn1octetstring)seq.getobjectat(1));
            // todo is it possible to get the order (n) and cofactor(h) too?
            curve = new eccurve.f2m(m, k1, k2, k3, x9a.getvalue().tobiginteger(), x9b.getvalue().tobiginteger());
        }
        else
        {
            throw new illegalargumentexception("this type of eccurve is not implemented");
        }

        if (seq.size() == 3)
        {
            seed = ((derbitstring)seq.getobjectat(2)).getbytes();
        }
    }

    private void setfieldidentifier()
    {
        if (curve instanceof eccurve.fp)
        {
            fieldidentifier = prime_field;
        }
        else if (curve instanceof eccurve.f2m)
        {
            fieldidentifier = characteristic_two_field;
        }
        else
        {
            throw new illegalargumentexception("this type of eccurve is not implemented");
        }
    }

    public eccurve  getcurve()
    {
        return curve;
    }

    public byte[]   getseed()
    {
        return seed;
    }

    /**
     * produce an object suitable for an asn1outputstream.
     * <pre>
     *  curve ::= sequence {
     *      a               fieldelement,
     *      b               fieldelement,
     *      seed            bit string      optional
     *  }
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        if (fieldidentifier.equals(prime_field)) 
        { 
            v.add(new x9fieldelement(curve.geta()).toasn1primitive());
            v.add(new x9fieldelement(curve.getb()).toasn1primitive());
        } 
        else if (fieldidentifier.equals(characteristic_two_field)) 
        {
            v.add(new x9fieldelement(curve.geta()).toasn1primitive());
            v.add(new x9fieldelement(curve.getb()).toasn1primitive());
        }

        if (seed != null)
        {
            v.add(new derbitstring(seed));
        }

        return new dersequence(v);
    }
}
