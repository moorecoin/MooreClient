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

public class mceliececca2privatekey
    extends asn1object
{
    private asn1objectidentifier oid;
    private int n;
    private int k;
    private byte[] encfield;
    private byte[] encgp;
    private byte[] encp;
    private byte[] ench;
    private byte[][] encqinv;


    public mceliececca2privatekey(asn1objectidentifier oid, int n, int k, gf2mfield field, polynomialgf2msmallm goppapoly, permutation p, gf2matrix h, polynomialgf2msmallm[] qinv)
    {
        this.oid = oid;
        this.n = n;
        this.k = k;
        this.encfield = field.getencoded();
        this.encgp = goppapoly.getencoded();
        this.encp = p.getencoded();
        this.ench = h.getencoded();
        this.encqinv = new byte[qinv.length][];

        for (int i = 0; i != qinv.length; i++)
        {
            encqinv[i] = qinv[i].getencoded();
        }
    }

    private mceliececca2privatekey(asn1sequence seq)
    {
        oid = ((asn1objectidentifier)seq.getobjectat(0));

        biginteger bign = ((asn1integer)seq.getobjectat(1)).getvalue();
        n = bign.intvalue();

        biginteger bigk = ((asn1integer)seq.getobjectat(2)).getvalue();
        k = bigk.intvalue();

        encfield = ((asn1octetstring)seq.getobjectat(3)).getoctets();

        encgp = ((asn1octetstring)seq.getobjectat(4)).getoctets();

        encp = ((asn1octetstring)seq.getobjectat(5)).getoctets();

        ench = ((asn1octetstring)seq.getobjectat(6)).getoctets();

        asn1sequence asnqinv = (asn1sequence)seq.getobjectat(7);
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

    public permutation getp()
    {
        return new permutation(encp);
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

        // encode <field>
        v.add(new deroctetstring(encfield));

        // encode <gp>
        v.add(new deroctetstring(encgp));

        // encode <p>
        v.add(new deroctetstring(encp));

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

    public static mceliececca2privatekey getinstance(object o)
    {
        if (o instanceof mceliececca2privatekey)
        {
            return (mceliececca2privatekey)o;
        }
        else if (o != null)
        {
            return new mceliececca2privatekey(asn1sequence.getinstance(o));
        }

        return null;
    }
}
