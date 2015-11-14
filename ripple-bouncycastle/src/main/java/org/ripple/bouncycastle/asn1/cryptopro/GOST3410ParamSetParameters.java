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

public class gost3410paramsetparameters
    extends asn1object
{
    int             keysize;
    asn1integer      p, q, a;

    public static gost3410paramsetparameters getinstance(
        asn1taggedobject obj,
        boolean          explicit)
    {
        return getinstance(asn1sequence.getinstance(obj, explicit));
    }

    public static gost3410paramsetparameters getinstance(
        object obj)
    {
        if(obj == null || obj instanceof gost3410paramsetparameters)
        {
            return (gost3410paramsetparameters)obj;
        }

        if(obj instanceof asn1sequence)
        {
            return new gost3410paramsetparameters((asn1sequence)obj);
        }

        throw new illegalargumentexception("invalid gost3410parameter: " + obj.getclass().getname());
    }

    public gost3410paramsetparameters(
        int keysize,
        biginteger  p,
        biginteger  q,
        biginteger  a)
    {
        this.keysize = keysize;
        this.p = new asn1integer(p);
        this.q = new asn1integer(q);
        this.a = new asn1integer(a);
    }

    public gost3410paramsetparameters(
        asn1sequence  seq)
    {
        enumeration     e = seq.getobjects();

        keysize = ((asn1integer)e.nextelement()).getvalue().intvalue();
        p = (asn1integer)e.nextelement();
        q = (asn1integer)e.nextelement();
        a = (asn1integer)e.nextelement();
    }

    /**
     * @deprecated use getkeysize
     */
    public int getlkeysize()
    {
        return keysize;
    }

    public int getkeysize()
    {
        return keysize;
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

        v.add(new asn1integer(keysize));
        v.add(p);
        v.add(q);
        v.add(a);

        return new dersequence(v);
    }
}
