package org.ripple.bouncycastle.asn1.ua;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;

public class dstu4145binaryfield
    extends asn1object
{

    private int m, k, j, l;

    private dstu4145binaryfield(asn1sequence seq)
    {
        m = asn1integer.getinstance(seq.getobjectat(0)).getpositivevalue().intvalue();

        if (seq.getobjectat(1) instanceof asn1integer)
        {
            k = ((asn1integer)seq.getobjectat(1)).getpositivevalue().intvalue();
        }
        else if (seq.getobjectat(1) instanceof asn1sequence)
        {
            asn1sequence coefs = asn1sequence.getinstance(seq.getobjectat(1));

            k = asn1integer.getinstance(coefs.getobjectat(0)).getpositivevalue().intvalue();
            j = asn1integer.getinstance(coefs.getobjectat(1)).getpositivevalue().intvalue();
            l = asn1integer.getinstance(coefs.getobjectat(2)).getpositivevalue().intvalue();
        }
        else
        {
            throw new illegalargumentexception("object parse error");
        }
    }

    public static dstu4145binaryfield getinstance(object obj)
    {
        if (obj instanceof dstu4145binaryfield)
        {
            return (dstu4145binaryfield)obj;
        }

        if (obj != null)
        {
            return new dstu4145binaryfield(asn1sequence.getinstance(obj));
        }

        return null;
    }

    public dstu4145binaryfield(int m, int k1, int k2, int k3)
    {
        this.m = m;
        this.k = k1;
        this.j = k2;
        this.l = k3;
    }

    public int getm()
    {
        return m;
    }

    public int getk1()
    {
        return k;
    }

    public int getk2()
    {
        return j;
    }

    public int getk3()
    {
        return l;
    }

    public dstu4145binaryfield(int m, int k)
    {
        this(m, k, 0, 0);
    }

    /**
     * binaryfield ::= sequence {
     * m integer,
     * choice {trinomial,    pentanomial}
     * trinomial::= integer
     * pentanomial::= sequence {
     * k integer,
     * j integer,
     * l integer}
     */
    public asn1primitive toasn1primitive()
    {

        asn1encodablevector v = new asn1encodablevector();

        v.add(new asn1integer(m));
        if (j == 0) //trinomial
        {
            v.add(new asn1integer(k));
        }
        else
        {
            asn1encodablevector coefs = new asn1encodablevector();
            coefs.add(new asn1integer(k));
            coefs.add(new asn1integer(j));
            coefs.add(new asn1integer(l));

            v.add(new dersequence(coefs));
        }

        return new dersequence(v);
    }

}
