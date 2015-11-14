package org.ripple.bouncycastle.asn1.pkcs;

import java.math.biginteger;
import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.deroctetstring;
import org.ripple.bouncycastle.asn1.dersequence;

public class pbkdf2params
    extends asn1object
{
    private asn1octetstring octstr;
    private asn1integer      iterationcount;
    private asn1integer      keylength;

    public static pbkdf2params getinstance(
        object  obj)
    {
        if (obj instanceof pbkdf2params)
        {
            return (pbkdf2params)obj;
        }

        if (obj != null)
        {
            return new pbkdf2params(asn1sequence.getinstance(obj));
        }

        return null;
    }
    
    public pbkdf2params(
        byte[]  salt,
        int     iterationcount)
    {
        this.octstr = new deroctetstring(salt);
        this.iterationcount = new asn1integer(iterationcount);
    }

    public pbkdf2params(
        byte[]  salt,
        int     iterationcount,
        int     keylength)
    {
        this(salt, iterationcount);

        this.keylength = new asn1integer(keylength);
    }

    private pbkdf2params(
        asn1sequence  seq)
    {
        enumeration e = seq.getobjects();

        octstr = (asn1octetstring)e.nextelement();
        iterationcount = (asn1integer)e.nextelement();

        if (e.hasmoreelements())
        {
            keylength = (asn1integer)e.nextelement();
        }
        else
        {
            keylength = null;
        }
    }

    public byte[] getsalt()
    {
        return octstr.getoctets();
    }

    public biginteger getiterationcount()
    {
        return iterationcount.getvalue();
    }

    public biginteger getkeylength()
    {
        if (keylength != null)
        {
            return keylength.getvalue();
        }

        return null;
    }

    public asn1primitive toasn1primitive()
    {
        asn1encodablevector  v = new asn1encodablevector();

        v.add(octstr);
        v.add(iterationcount);

        if (keylength != null)
        {
            v.add(keylength);
        }

        return new dersequence(v);
    }
}
