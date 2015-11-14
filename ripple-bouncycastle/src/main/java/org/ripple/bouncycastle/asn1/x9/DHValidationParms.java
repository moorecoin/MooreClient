package org.ripple.bouncycastle.asn1.x9;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.derbitstring;
import org.ripple.bouncycastle.asn1.dersequence;

public class dhvalidationparms extends asn1object
{
    private derbitstring seed;
    private asn1integer pgencounter;

    public static dhvalidationparms getinstance(asn1taggedobject obj, boolean explicit)
    {
        return getinstance(asn1sequence.getinstance(obj, explicit));
    }

    public static dhvalidationparms getinstance(object obj)
    {
        if (obj == null || obj instanceof dhdomainparameters)
        {
            return (dhvalidationparms)obj;
        }

        if (obj instanceof asn1sequence)
        {
            return new dhvalidationparms((asn1sequence)obj);
        }

        throw new illegalargumentexception("invalid dhvalidationparms: " + obj.getclass().getname());
    }

    public dhvalidationparms(derbitstring seed, asn1integer pgencounter)
    {
        if (seed == null)
        {
            throw new illegalargumentexception("'seed' cannot be null");
        }
        if (pgencounter == null)
        {
            throw new illegalargumentexception("'pgencounter' cannot be null");
        }

        this.seed = seed;
        this.pgencounter = pgencounter;
    }

    private dhvalidationparms(asn1sequence seq)
    {
        if (seq.size() != 2)
        {
            throw new illegalargumentexception("bad sequence size: " + seq.size());
        }

        this.seed = derbitstring.getinstance(seq.getobjectat(0));
        this.pgencounter = asn1integer.getinstance(seq.getobjectat(1));
    }

    public derbitstring getseed()
    {
        return this.seed;
    }

    public asn1integer getpgencounter()
    {
        return this.pgencounter;
    }

    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();
        v.add(this.seed);
        v.add(this.pgencounter);
        return new dersequence(v);
    }
}
