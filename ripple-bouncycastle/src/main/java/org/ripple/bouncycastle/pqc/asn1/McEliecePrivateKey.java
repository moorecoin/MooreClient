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
import org.ripple.bouncycastle.pqc.math.linearalgebra.gf2mfield;
import org.ripple.bouncycastle.pqc.math.linearalgebra.permutation;
import org.ripple.bouncycastle.pqc.math.linearalgebra.polynomialgf2msmallm;

public class mcelieceprivatekey
    extends asn1object
{
    private asn1objectidentifier oid;
    private int n;
    private int k;
    private byte[] encfield;
    private byte[] encgp;
    private byte[] encsinv;
    private byte[] encp1;
    private byte[] encp2;
    private byte[] ench;
    private byte[][] encqinv;


    public mcelieceprivatekey(asn1objectidentifier oid, int n, int k, gf2mfield field, polynomialgf2msmallm goppapoly, gf2matrix sinv, permutation p1, permutation p2, gf2matrix h, polynomialgf2msmallm[] qinv)
    {
        this.oid = oid;
        this.n = n;
        this.k = k;
        this.encfield = field.getencoded();
        this.encgp = goppapoly.getencoded();
        this.encsinv = sinv.getencoded();
        this.encp1 = p1.getencoded();
        this.encp2 = p2.getencoded();
        this.ench = h.getencoded();
        this.encqinv = new byte[qinv.length][];

        for (int i = 0; i != qinv.length; i++)
        {
            encqinv[i] = qinv[i].getencoded();
        }
    }

    public static mcelieceprivatekey getinstance(object o)
    {
        if (o instanceof mcelieceprivatekey)
        {
            return (mcelieceprivatekey)o;
        }
        else if (o != null)
        {
            return new mcelieceprivatekey(asn1sequence.getinstance(o));
        }

        return null;
    }

    private mcelieceprivatekey(asn1sequence seq)
    {
        // <oidstring>
        oid = ((asn1objectidentifier)seq.getobjectat(0));

        biginteger bign = ((asn1integer)seq.getobjectat(1)).getvalue();
        n = bign.intvalue();

        biginteger bigk = ((asn1integer)seq.getobjectat(2)).getvalue();
        k = bigk.intvalue();

        encfield = ((asn1octetstring)seq.getobjectat(3)).getoctets();

        encgp = ((asn1octetstring)seq.getobjectat(4)).getoctets();

        encsinv = ((asn1octetstring)seq.getobjectat(5)).getoctets();

        encp1 = ((asn1octetstring)seq.getobjectat(6)).getoctets();

        encp2 = ((asn1octetstring)seq.getobjectat(7)).getoctets();

        ench = ((asn1octetstring)seq.getobjectat(8)).getoctets();

        asn1sequence asnqinv = (asn1sequence)seq.getobjectat(9);
        encqinv = new byte[asnqinv.size()][];
        for (int i = 0; i < asnqinv.size(); i++)
        {
            encqinv[i] = ((asn1octetstring)asnqinv.getobjectat(i)).getoctets();
        }
    }

    public asn1objectidentifier getoid()
    {
        return oid;
    }

    public int getn()
    {
        return n;
    }

    public int getk()
    {
        return k;
    }

    public gf2mfield getfield()
    {
        return new gf2mfield(encfield);
    }

    public polynomialgf2msmallm getgoppapoly()
    {
        return new polynomialgf2msmallm(this.getfield(), encgp);
    }

    public gf2matrix getsinv()
    {
        return new gf2matrix(encsinv);
    }

    public permutation getp1()
    {
        return new permutation(encp1);
    }

    public permutation getp2()
    {
        return new permutation(encp2);
    }

    public gf2matrix geth()
    {
        return new gf2matrix(ench);
    }

    public polynomialgf2msmallm[] getqinv()
    {
        polynomialgf2msmallm[] qinv = new polynomialgf2msmallm[encqinv.length];
        gf2mfield field = this.getfield();

        for (int i = 0; i < encqinv.length; i++)
        {
            qinv[i] = new polynomialgf2msmallm(field, encqinv[i]);
        }

        return qinv;
    }

    public asn1primitive toasn1primitive()
    {

        asn1encodablevector v = new asn1encodablevector();
        // encode <oidstring>
        v.add(oid);
        // encode <n>
        v.add(new asn1integer(n));

        // encode <k>
        v.add(new asn1integer(k));

        // encode <fieldpoly>
        v.add(new deroctetstring(encfield));

        // encode <goppapoly>
        v.add(new deroctetstring(encgp));

        // encode <sinv>
        v.add(new deroctetstring(encsinv));

        // encode <p1>
        v.add(new deroctetstring(encp1));

        // encode <p2>
        v.add(new deroctetstring(encp2));

        // encode <h>
        v.add(new deroctetstring(ench));

        // encode <q>
        asn1encodablevector asnqinv = new asn1encodablevector();
        for (int i = 0; i < encqinv.length; i++)
        {
            asnqinv.add(new deroctetstring(encqinv[i]));
        }

        v.add(new dersequence(asnqinv));

        return new dersequence(v);
    }
}
