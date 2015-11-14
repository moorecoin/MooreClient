package org.ripple.bouncycastle.asn1.ua;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.deroctetstring;
import org.ripple.bouncycastle.asn1.dersequence;

public class dstu4145params
    extends asn1object
{
    private static final byte default_dke[] = {
        (byte)0xa9, (byte)0xd6, (byte)0xeb, 0x45, (byte)0xf1, 0x3c, 0x70, (byte)0x82,
        (byte)0x80, (byte)0xc4, (byte)0x96, 0x7b, 0x23, 0x1f, 0x5e, (byte)0xad,
        (byte)0xf6, 0x58, (byte)0xeb, (byte)0xa4, (byte)0xc0, 0x37, 0x29, 0x1d,
        0x38, (byte)0xd9, 0x6b, (byte)0xf0, 0x25, (byte)0xca, 0x4e, 0x17,
        (byte)0xf8, (byte)0xe9, 0x72, 0x0d, (byte)0xc6, 0x15, (byte)0xb4, 0x3a,
        0x28, (byte)0x97, 0x5f, 0x0b, (byte)0xc1, (byte)0xde, (byte)0xa3, 0x64,
        0x38, (byte)0xb5, 0x64, (byte)0xea, 0x2c, 0x17, (byte)0x9f, (byte)0xd0,
        0x12, 0x3e, 0x6d, (byte)0xb8, (byte)0xfa, (byte)0xc5, 0x79, 0x04};


    private asn1objectidentifier namedcurve;
    private dstu4145ecbinary ecbinary;
    private byte[] dke = default_dke;

    public dstu4145params(asn1objectidentifier namedcurve)
    {
        this.namedcurve = namedcurve;
    }

    public dstu4145params(dstu4145ecbinary ecbinary)
    {
        this.ecbinary = ecbinary;
    }

    public boolean isnamedcurve()
    {
        return namedcurve != null;
    }

    public dstu4145ecbinary getecbinary()
    {
        return ecbinary;
    }

    public byte[] getdke()
    {
        return dke;
    }

    public static byte[] getdefaultdke()
    {
        return default_dke;
    }

    public asn1objectidentifier getnamedcurve()
    {
        return namedcurve;
    }

    public static dstu4145params getinstance(object obj)
    {
        if (obj instanceof dstu4145params)
        {
            return (dstu4145params)obj;
        }

        if (obj != null)
        {
            asn1sequence seq = asn1sequence.getinstance(obj);
            dstu4145params params;

            if (seq.getobjectat(0) instanceof asn1objectidentifier)
            {
                params = new dstu4145params(asn1objectidentifier.getinstance(seq.getobjectat(0)));
            }
            else
            {
                params = new dstu4145params(dstu4145ecbinary.getinstance(seq.getobjectat(0)));
            }

            if (seq.size() == 2)
            {
                params.dke = asn1octetstring.getinstance(seq.getobjectat(1)).getoctets();
                if (params.dke.length != dstu4145params.default_dke.length)
                {
                    throw new illegalargumentexception("object parse error");
                }
            }

            return params;
        }

        throw new illegalargumentexception("object parse error");
    }

    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        if (namedcurve != null)
        {
            v.add(namedcurve);
        }
        else
        {
            v.add(ecbinary);
        }

        if (!org.ripple.bouncycastle.util.arrays.areequal(dke, default_dke))
        {
            v.add(new deroctetstring(dke));
        }

        return new dersequence(v);
    }
}
