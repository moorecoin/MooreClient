package org.ripple.bouncycastle.pqc.asn1;

import java.math.biginteger;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.deroctetstring;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.pqc.math.linearalgebra.gf2matrix;

public class mceliececca2publickey
    extends asn1object
{
    private asn1objectidentifier oid;
    private int n;
    private int t;

    private byte[] matrixg;

    public mceliececca2publickey(asn1objectidentifier oid, int n, int t, gf2matrix g)
    {
        this.oid = oid;
        this.n = n;
        this.t = t;
        this.matrixg = g.getencoded();
    }

    private mceliececca2publickey(asn1sequence seq)
    {
        oid = ((asn1objectidentifier)seq.getobjectat(0));
        biginteger bign = ((asn1integer)seq.getobjectat(1)).getvalue();
        n = bign.intvalue();

        biginteger bigt = ((asn1integer)seq.getobjectat(2)).getvalue();
        t = bigt.intvalue();

        matrixg = ((asn1octetstring)seq.getobjectat(3)).getoctets();
    }

    public asn1objectidentifier getoid()
    {
        return oid;
    }

    public int getn()
    {
        return n;
    }

    public int gett()
    {
        return t;
    }

    public gf2matrix getg()
    {
        return new gf2matrix(matrixg);
    }

    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();
        // encode <oidstring>
        v.add(oid);

        // encode <n>
        v.add(new asn1integer(n));

        // encode <t>
        v.add(new asn1integer(t));

        // encode <matrixg>
        v.add(new deroctetstring(matrixg));

        return new dersequence(v);
    }

    public static mceliececca2publickey getinstance(object o)
    {
        if (o instanceof mceliececca2publickey)
        {
            return (mceliececca2publickey)o;
        }
        else if (o != null)
        {
            return new mceliececca2publickey(asn1sequence.getinstance(o));
        }

        return null;
    }
}
