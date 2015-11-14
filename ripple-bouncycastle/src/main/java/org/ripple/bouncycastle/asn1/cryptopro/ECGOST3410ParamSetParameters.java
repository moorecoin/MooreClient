package org.ripple.bouncycastle.asn1.cryptopro;

import java.math.biginteger;
import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dersequence;

public class ecgost3410paramsetparameters
    extends asn1object
{
    asn1integer      p, q, a, b, x, y;

    public static ecgost3410paramsetparameters getinstance(
        asn1taggedobject obj,
        boolean          explicit)
    {
        return getinstance(asn1sequence.getinstance(obj, explicit));
    }

    public static ecgost3410paramsetparameters getinstance(
        object obj)
    {
        if(obj == null || obj instanceof ecgost3410paramsetparameters)
        {
            return (ecgost3410paramsetparameters)obj;
        }

        if(obj instanceof asn1sequence)
        {
            return new ecgost3410paramsetparameters((asn1sequence)obj);
        }

        throw new illegalargumentexception("invalid gost3410parameter: " + obj.getclass().getname());
    }

    public ecgost3410paramsetparameters(
        biginteger a,
        biginteger b,
        biginteger p,
        biginteger q,
        int        x,
        biginteger y)
    {
        this.a = new asn1integer(a);
        this.b = new asn1integer(b);
        this.p = new asn1integer(p);
        this.q = new asn1integer(q);
        this.x = new asn1integer(x);
        this.y = new asn1integer(y);
    }

    public ecgost3410paramsetparameters(
        asn1sequence  seq)
    {
        enumeration     e = seq.getobjects();

        a = (asn1integer)e.nextelement();
        b = (asn1integer)e.nextelement();
        p = (asn1integer)e.nextelement();
        q = (asn1integer)e.nextelement();
        x = (asn1integer)e.nextelement();
        y = (asn1integer)e.nextelement();
    }
    
    public biginteger getp()
    {
        return p.getpositivevalue();
    }

    public biginteger getq()
    {
        return q.getpositivevalue();
    }

    public biginteger geta()
    {
        return a.getpositivevalue();
    }

    public asn1primitive toasn1primitive()
    {
        asn1encodablevector  v = new asn1encodablevector();

        v.add(a);
        v.add(b);
        v.add(p);
        v.add(q);
        v.add(x);
        v.add(y);

        return new dersequence(v);
    }
}
