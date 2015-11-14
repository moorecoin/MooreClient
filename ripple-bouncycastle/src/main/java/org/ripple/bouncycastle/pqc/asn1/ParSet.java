package org.ripple.bouncycastle.pqc.asn1;

import java.math.biginteger;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.util.arrays;

/**
 * <pre>
 *  parset              ::= sequence {
 *      t               integer
 *      h               sequence of integer
 *      w               sequence of integer
 *      k               sequence of integer
 *  }
 * </pre>
 */
public class parset
    extends asn1object
{
    private static final biginteger zero = biginteger.valueof(0);

    private int   t;
    private int[] h;
    private int[] w;
    private int[] k;

    private static int checkbigintegerinintrangeandpositive(biginteger b)
    {
        if ((b.compareto(biginteger.valueof(integer.max_value)) > 0) ||
            (b.compareto(zero) <= 0))
        {
            throw new illegalargumentexception("biginteger not in range: " + b.tostring());
        }
        return b.intvalue();
    }

    private parset(asn1sequence seq)
    {
        if (seq.size() != 4)
        {
            throw new illegalargumentexception("sie of seqofparams = " + seq.size());
        }
        biginteger asn1int = ((asn1integer)seq.getobjectat(0)).getvalue();

        t = checkbigintegerinintrangeandpositive(asn1int);

        asn1sequence seqofpsh = (asn1sequence)seq.getobjectat(1);
        asn1sequence seqofpsw = (asn1sequence)seq.getobjectat(2);
        asn1sequence seqofpsk = (asn1sequence)seq.getobjectat(3);

        if ((seqofpsh.size() != t) ||
            (seqofpsw.size() != t) ||
            (seqofpsk.size() != t))
        {
            throw new illegalargumentexception("invalid size of sequences");
        }

        h = new int[seqofpsh.size()];
        w = new int[seqofpsw.size()];
        k = new int[seqofpsk.size()];

        for (int i = 0; i < t; i++)
        {
            h[i] = checkbigintegerinintrangeandpositive((((asn1integer)seqofpsh.getobjectat(i))).getvalue());
            w[i] = checkbigintegerinintrangeandpositive((((asn1integer)seqofpsw.getobjectat(i))).getvalue());
            k[i] = checkbigintegerinintrangeandpositive((((asn1integer)seqofpsk.getobjectat(i))).getvalue());
        }
    }

    public parset(int t, int[] h, int[] w, int[] k)
    {
        this.t = t;
        this.h = h;
        this.w = w;
        this.k = k;
    }

    public static parset getinstance(object o)
    {
        if (o instanceof parset)
        {
            return (parset)o;
        }
        else if (o != null)
        {
            return new parset(asn1sequence.getinstance(o));
        }

        return null;
    }

    public int gett()
    {
        return t;
    }

    public int[] geth()
    {
        return arrays.clone(h);
    }

    public int[] getw()
    {
        return arrays.clone(w);
    }

    public int[] getk()
    {
        return arrays.clone(k);
    }

    public asn1primitive toasn1primitive()
    {
        asn1encodablevector seqofpsh = new asn1encodablevector();
        asn1encodablevector seqofpsw = new asn1encodablevector();
        asn1encodablevector seqofpsk = new asn1encodablevector();

        for (int i = 0; i < h.length; i++)
        {
            seqofpsh.add(new asn1integer(h[i]));
            seqofpsw.add(new asn1integer(w[i]));
            seqofpsk.add(new asn1integer(k[i]));
        }

        asn1encodablevector v = new asn1encodablevector();

        v.add(new asn1integer(t));
        v.add(new dersequence(seqofpsh));
        v.add(new dersequence(seqofpsw));
        v.add(new dersequence(seqofpsk));

        return new dersequence(v);
    }
}
