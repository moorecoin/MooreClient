package org.ripple.bouncycastle.asn1.esf;

import java.math.biginteger;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1utctime;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.x500.x500name;

/**
 * <pre>
 *  crlidentifier ::= sequence 
 * {
 *   crlissuer    name,
 *   crlissuedtime  utctime,
 *   crlnumber    integer optional
 * }
 * </pre>
 */
public class crlidentifier
    extends asn1object
{
    private x500name crlissuer;
    private asn1utctime crlissuedtime;
    private asn1integer crlnumber;

    public static crlidentifier getinstance(object obj)
    {
        if (obj instanceof crlidentifier)
        {
            return (crlidentifier)obj;
        }
        else if (obj != null)
        {
            return new crlidentifier(asn1sequence.getinstance(obj));
        }

        return null;
    }

    private crlidentifier(asn1sequence seq)
    {
        if (seq.size() < 2 || seq.size() > 3)
        {
            throw new illegalargumentexception();
        }
        this.crlissuer = x500name.getinstance(seq.getobjectat(0));
        this.crlissuedtime = asn1utctime.getinstance(seq.getobjectat(1));
        if (seq.size() > 2)
        {
            this.crlnumber = asn1integer.getinstance(seq.getobjectat(2));
        }
    }

    public crlidentifier(x500name crlissuer, asn1utctime crlissuedtime)
    {
        this(crlissuer, crlissuedtime, null);
    }

    public crlidentifier(x500name crlissuer, asn1utctime crlissuedtime,
                         biginteger crlnumber)
    {
        this.crlissuer = crlissuer;
        this.crlissuedtime = crlissuedtime;
        if (null != crlnumber)
        {
            this.crlnumber = new asn1integer(crlnumber);
        }
    }

    public x500name getcrlissuer()
    {
        return this.crlissuer;
    }

    public asn1utctime getcrlissuedtime()
    {
        return this.crlissuedtime;
    }

    public biginteger getcrlnumber()
    {
        if (null == this.crlnumber)
        {
            return null;
        }
        return this.crlnumber.getvalue();
    }

    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();
        v.add(this.crlissuer.toasn1primitive());
        v.add(this.crlissuedtime);
        if (null != this.crlnumber)
        {
            v.add(this.crlnumber);
        }
        return new dersequence(v);
    }

}
