package org.ripple.bouncycastle.asn1.eac;

import java.math.biginteger;
import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.deroctetstring;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;

/**
 * an iso7816ecdsapublickeystructure structure.
 * <p/>
 * <pre>
 *  certificate holder authorization ::= sequence {
 *      asn1taggedobject primemodulusp;        // optional
 *      asn1taggedobject firstcoefa;            // optional
 *      asn1taggedobject secondcoefb;        // optional
 *      asn1taggedobject basepointg;            // optional
 *      asn1taggedobject orderofbasepointr;    // optional
 *      asn1taggedobject publicpointy;        //required
 *      asn1taggedobject    cofactorf;            // optional
 *  }
 * </pre>
 */
public class ecdsapublickey
    extends publickeydataobject
{
    private asn1objectidentifier usage;
    private biginteger primemodulusp;        // optional
    private biginteger firstcoefa;            // optional
    private biginteger secondcoefb;        // optional
    private byte[]     basepointg;            // optional
    private biginteger orderofbasepointr;    // optional
    private byte[]     publicpointy;        //required
    private biginteger cofactorf;            // optional
    private int options;
    private static final int p = 0x01;
    private static final int a = 0x02;
    private static final int b = 0x04;
    private static final int g = 0x08;
    private static final int r = 0x10;
    private static final int y = 0x20;
    private static final int f = 0x40;

    ecdsapublickey(asn1sequence seq)
        throws illegalargumentexception
    {
        enumeration en = seq.getobjects();

        this.usage = asn1objectidentifier.getinstance(en.nextelement());

        options = 0;
        while (en.hasmoreelements())
        {
            object obj = en.nextelement();
            
            if (obj instanceof asn1taggedobject)
            {
                asn1taggedobject to = (asn1taggedobject)obj;
                switch (to.gettagno())
                {
                case 0x1:
                    setprimemodulusp(unsignedinteger.getinstance(to).getvalue());
                    break;
                case 0x2:
                    setfirstcoefa(unsignedinteger.getinstance(to).getvalue());
                    break;
                case 0x3:
                    setsecondcoefb(unsignedinteger.getinstance(to).getvalue());
                    break;
                case 0x4:
                    setbasepointg(asn1octetstring.getinstance(to, false));
                    break;
                case 0x5:
                    setorderofbasepointr(unsignedinteger.getinstance(to).getvalue());
                    break;
                case 0x6:
                    setpublicpointy(asn1octetstring.getinstance(to, false));
                    break;
                case 0x7:
                    setcofactorf(unsignedinteger.getinstance(to).getvalue());
                    break;
                default:
                    options = 0;
                    throw new illegalargumentexception("unknown object identifier!");
                }
            }
            else
            {
                throw new illegalargumentexception("unknown object identifier!");
            }
        }
        if (options != 0x20 && options != 0x7f)
        {
            throw new illegalargumentexception("all options must be either present or absent!");
        }
    }

    public ecdsapublickey(asn1objectidentifier usage, byte[] ppy)
        throws illegalargumentexception
    {
        this.usage = usage;
        setpublicpointy(new deroctetstring(ppy));
    }

    public ecdsapublickey(asn1objectidentifier usage, biginteger p, biginteger a, biginteger b, byte[] basepoint, biginteger order, byte[] publicpoint, int cofactor)
    {
        this.usage = usage;
        setprimemodulusp(p);
        setfirstcoefa(a);
        setsecondcoefb(b);
        setbasepointg(new deroctetstring(basepoint));
        setorderofbasepointr(order);
        setpublicpointy(new deroctetstring(publicpoint));
        setcofactorf(biginteger.valueof(cofactor));
    }

    public asn1objectidentifier getusage()
    {
        return usage;
    }

    public byte[] getbasepointg()
    {
        if ((options & g) != 0)
        {
            return basepointg;
        }
        else
        {
            return null;
        }
    }

    private void setbasepointg(asn1octetstring basepointg)
        throws illegalargumentexception
    {
        if ((options & g) == 0)
        {
            options |= g;
            this.basepointg = basepointg.getoctets();
        }
        else
        {
            throw new illegalargumentexception("base point g already set");
        }
    }

    public biginteger getcofactorf()
    {
        if ((options & f) != 0)
        {
            return cofactorf;
        }
        else
        {
            return null;
        }
    }

    private void setcofactorf(biginteger cofactorf)
        throws illegalargumentexception
    {
        if ((options & f) == 0)
        {
            options |= f;
            this.cofactorf = cofactorf;
        }
        else
        {
            throw new illegalargumentexception("cofactor f already set");
        }
    }

    public biginteger getfirstcoefa()
    {
        if ((options & a) != 0)
        {
            return firstcoefa;
        }
        else
        {
            return null;
        }
    }

    private void setfirstcoefa(biginteger firstcoefa)
        throws illegalargumentexception
    {
        if ((options & a) == 0)
        {
            options |= a;
            this.firstcoefa = firstcoefa;
        }
        else
        {
            throw new illegalargumentexception("first coef a already set");
        }
    }

    public biginteger getorderofbasepointr()
    {
        if ((options & r) != 0)
        {
            return orderofbasepointr;
        }
        else
        {
            return null;
        }
    }

    private void setorderofbasepointr(biginteger orderofbasepointr)
        throws illegalargumentexception
    {
        if ((options & r) == 0)
        {
            options |= r;
            this.orderofbasepointr = orderofbasepointr;
        }
        else
        {
            throw new illegalargumentexception("order of base point r already set");
        }
    }

    public biginteger getprimemodulusp()
    {
        if ((options & p) != 0)
        {
            return primemodulusp;
        }
        else
        {
            return null;
        }
    }

    private void setprimemodulusp(biginteger primemodulusp)
    {
        if ((options & p) == 0)
        {
            options |= p;
            this.primemodulusp = primemodulusp;
        }
        else
        {
            throw new illegalargumentexception("prime modulus p already set");
        }
    }

    public byte[] getpublicpointy()
    {
        if ((options & y) != 0)
        {
            return publicpointy;
        }
        else
        {
            return null;
        }
    }

    private void setpublicpointy(asn1octetstring publicpointy)
        throws illegalargumentexception
    {
        if ((options & y) == 0)
        {
            options |= y;
            this.publicpointy = publicpointy.getoctets();
        }
        else
        {
            throw new illegalargumentexception("public point y already set");
        }
    }

    public biginteger getsecondcoefb()
    {
        if ((options & b) != 0)
        {
            return secondcoefb;
        }
        else
        {
            return null;
        }
    }

    private void setsecondcoefb(biginteger secondcoefb)
        throws illegalargumentexception
    {
        if ((options & b) == 0)
        {
            options |= b;
            this.secondcoefb = secondcoefb;
        }
        else
        {
            throw new illegalargumentexception("second coef b already set");
        }
    }

    public boolean hasparameters()
    {
        return primemodulusp != null;
    }

    public asn1encodablevector getasn1encodablevector(asn1objectidentifier oid, boolean publicpointonly)
    {
        asn1encodablevector v = new asn1encodablevector();
        v.add(oid);

        if (!publicpointonly)
        {
            v.add(new unsignedinteger(0x01, getprimemodulusp()));
            v.add(new unsignedinteger(0x02, getfirstcoefa()));
            v.add(new unsignedinteger(0x03, getsecondcoefb()));
            v.add(new dertaggedobject(false, 0x04, new deroctetstring(getbasepointg())));
            v.add(new unsignedinteger(0x05, getorderofbasepointr()));
        }
        v.add(new dertaggedobject(false, 0x06, new deroctetstring(getpublicpointy())));
        if (!publicpointonly)
        {
            v.add(new unsignedinteger(0x07, getcofactorf()));
        }

        return v;
    }

    public asn1primitive toasn1primitive()
    {
        return new dersequence(getasn1encodablevector(usage, false));
    }
}
