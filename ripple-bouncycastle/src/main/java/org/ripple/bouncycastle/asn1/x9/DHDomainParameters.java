package org.ripple.bouncycastle.asn1.x9;

import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dersequence;

public class dhdomainparameters
    extends asn1object
{
    private asn1integer p, g, q, j;
    private dhvalidationparms validationparms;

    public static dhdomainparameters getinstance(asn1taggedobject obj, boolean explicit)
    {
        return getinstance(asn1sequence.getinstance(obj, explicit));
    }

    public static dhdomainparameters getinstance(object obj)
    {
        if (obj == null || obj instanceof dhdomainparameters)
        {
            return (dhdomainparameters)obj;
        }

        if (obj instanceof asn1sequence)
        {
            return new dhdomainparameters((asn1sequence)obj);
        }

        throw new illegalargumentexception("invalid dhdomainparameters: "
            + obj.getclass().getname());
    }

    public dhdomainparameters(asn1integer p, asn1integer g, asn1integer q, asn1integer j,
        dhvalidationparms validationparms)
    {
        if (p == null)
        {
            throw new illegalargumentexception("'p' cannot be null");
        }
        if (g == null)
        {
            throw new illegalargumentexception("'g' cannot be null");
        }
        if (q == null)
        {
            throw new illegalargumentexception("'q' cannot be null");
        }

        this.p = p;
        this.g = g;
        this.q = q;
        this.j = j;
        this.validationparms = validationparms;
    }

    private dhdomainparameters(asn1sequence seq)
    {
        if (seq.size() < 3 || seq.size() > 5)
        {
            throw new illegalargumentexception("bad sequence size: " + seq.size());
        }

        enumeration e = seq.getobjects();
        this.p = asn1integer.getinstance(e.nextelement());
        this.g = asn1integer.getinstance(e.nextelement());
        this.q = asn1integer.getinstance(e.nextelement());

        asn1encodable next = getnext(e);

        if (next != null && next instanceof asn1integer)
        {
            this.j = asn1integer.getinstance(next);
            next = getnext(e);
        }

        if (next != null)
        {
            this.validationparms = dhvalidationparms.getinstance(next.toasn1primitive());
        }
    }

    private static asn1encodable getnext(enumeration e)
    {
        return e.hasmoreelements() ? (asn1encodable)e.nextelement() : null;
    }

    public asn1integer getp()
    {
        return this.p;
    }

    public asn1integer getg()
    {
        return this.g;
    }

    public asn1integer getq()
    {
        return this.q;
    }

    public asn1integer getj()
    {
        return this.j;
    }

    public dhvalidationparms getvalidationparms()
    {
        return this.validationparms;
    }

    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();
        v.add(this.p);
        v.add(this.g);
        v.add(this.q);

        if (this.j != null)
        {
            v.add(this.j);
        }

        if (this.validationparms != null)
        {
            v.add(this.validationparms);
        }

        return new dersequence(v);
    }
}
