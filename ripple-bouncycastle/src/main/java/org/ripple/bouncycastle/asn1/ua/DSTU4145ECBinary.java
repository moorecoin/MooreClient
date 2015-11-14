package org.ripple.bouncycastle.asn1.ua;

import java.math.biginteger;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.deroctetstring;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;
import org.ripple.bouncycastle.asn1.x9.x9integerconverter;
import org.ripple.bouncycastle.crypto.params.ecdomainparameters;
import org.ripple.bouncycastle.math.ec.eccurve;
import org.ripple.bouncycastle.util.arrays;

public class dstu4145ecbinary
    extends asn1object
{

    biginteger version = biginteger.valueof(0);

    dstu4145binaryfield f;
    asn1integer a;
    asn1octetstring b;
    asn1integer n;
    asn1octetstring bp;

    public dstu4145ecbinary(ecdomainparameters params)
    {
        if (!(params.getcurve() instanceof eccurve.f2m))
        {
            throw new illegalargumentexception("only binary domain is possible");
        }

        // we always use big-endian in parameter encoding
        eccurve.f2m curve = (eccurve.f2m)params.getcurve();
        f = new dstu4145binaryfield(curve.getm(), curve.getk1(), curve.getk2(), curve.getk3());
        a = new asn1integer(curve.geta().tobiginteger());
        x9integerconverter converter = new x9integerconverter();
        b = new deroctetstring(converter.integertobytes(curve.getb().tobiginteger(), converter.getbytelength(curve)));
        n = new asn1integer(params.getn());
        bp = new deroctetstring(dstu4145pointencoder.encodepoint(params.getg()));
    }

    private dstu4145ecbinary(asn1sequence seq)
    {
        int index = 0;

        if (seq.getobjectat(index) instanceof asn1taggedobject)
        {
            asn1taggedobject taggedversion = (asn1taggedobject)seq.getobjectat(index);
            if (taggedversion.isexplicit() && 0 == taggedversion.gettagno())
            {
                version = asn1integer.getinstance(taggedversion.getloadedobject()).getvalue();
                index++;
            }
            else
            {
                throw new illegalargumentexception("object parse error");
            }
        }
        f = dstu4145binaryfield.getinstance(seq.getobjectat(index));
        index++;
        a = asn1integer.getinstance(seq.getobjectat(index));
        index++;
        b = asn1octetstring.getinstance(seq.getobjectat(index));
        index++;
        n = asn1integer.getinstance(seq.getobjectat(index));
        index++;
        bp = asn1octetstring.getinstance(seq.getobjectat(index));
    }

    public static dstu4145ecbinary getinstance(object obj)
    {
        if (obj instanceof dstu4145ecbinary)
        {
            return (dstu4145ecbinary)obj;
        }

        if (obj != null)
        {
            return new dstu4145ecbinary(asn1sequence.getinstance(obj));
        }

        return null;
    }

    public dstu4145binaryfield getfield()
    {
        return f;
    }

    public biginteger geta()
    {
        return a.getvalue();
    }

    public byte[] getb()
    {
        return arrays.clone(b.getoctets());
    }

    public biginteger getn()
    {
        return n.getvalue();
    }

    public byte[] getg()
    {
        return arrays.clone(bp.getoctets());
    }

    /**
     * ecbinary  ::= sequence {
     * version          [0] explicit integer    default 0,
     * f     binaryfield,
     * a    integer (0..1),
     * b    octet string,
     * n    integer,
     * bp    octet string}
     */
    public asn1primitive toasn1primitive()
    {

        asn1encodablevector v = new asn1encodablevector();

        if (0 != version.compareto(biginteger.valueof(0)))
        {
            v.add(new dertaggedobject(true, 0, new asn1integer(version)));
        }
        v.add(f);
        v.add(a);
        v.add(b);
        v.add(n);
        v.add(bp);

        return new dersequence(v);
    }

}
