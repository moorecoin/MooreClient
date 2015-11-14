package org.ripple.bouncycastle.asn1.x509;

import java.math.biginteger;
import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dersequence;

public class dsaparameter
    extends asn1object
{
    asn1integer      p, q, g;

    public static dsaparameter getinstance(
        asn1taggedobject obj,
        boolean          explicit)
    {
        return getinstance(asn1sequence.getinstance(obj, explicit));
    }

    public static dsaparameter getinstance(
        object obj)
    {
        if (obj instanceof dsaparameter)
        {
            return (dsaparameter)obj;
        }
        
        if(obj != null)
        {
            return new dsaparameter(asn1sequence.getinstance(obj));
        }
        
        return null;
    }

    public dsaparameter(
        biginteger  p,
        biginteger  q,
        biginteger  g)
    {
        this.p = new asn1integer(p);
        this.q = new asn1integer(q);
        this.g = new asn1integer(g);
    }

    private dsaparameter(
        asn1sequence  seq)
    {
        if (seq.size() != 3)
        {
            throw new illegalargumentexception("bad sequence size: " + seq.size());
        }
        
        enumeration     e = seq.getobjects();

        p = asn1integer.getinstance(e.nextelement());
        q = asn1integer.getinstance(e.nextelement());
        g = asn1integer.getinstance(e.nextelement());
    }

    public biginteger getp()
    {
        return p.getpositivevalue();
    }

    public biginteger getq()
    {
        return q.getpositivevalue();
    }

    public biginteger getg()
    {
        return g.getpositivevalue();
    }

    public asn1primitive toasn1primitive()
    {
        asn1encodablevector  v = new asn1encodablevector();

        v.add(p);
        v.add(q);
        v.add(g);

        return new dersequence(v);
    }
}
