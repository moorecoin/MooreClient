package org.ripple.bouncycastle.asn1.pkcs;

import java.math.biginteger;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.deroctetstring;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.x509.digestinfo;

public class macdata
    extends asn1object
{
    private static final biginteger one = biginteger.valueof(1);

    digestinfo                  diginfo;
    byte[]                      salt;
    biginteger                  iterationcount;

    public static macdata getinstance(
        object  obj)
    {
        if (obj instanceof macdata)
        {
            return (macdata)obj;
        }
        else if (obj != null)
        {
            return new macdata(asn1sequence.getinstance(obj));
        }

        return null;
    }

    private macdata(
        asn1sequence seq)
    {
        this.diginfo = digestinfo.getinstance(seq.getobjectat(0));

        this.salt = ((asn1octetstring)seq.getobjectat(1)).getoctets();

        if (seq.size() == 3)
        {
            this.iterationcount = ((asn1integer)seq.getobjectat(2)).getvalue();
        }
        else
        {
            this.iterationcount = one;
        }
    }

    public macdata(
        digestinfo  diginfo,
        byte[]      salt,
        int         iterationcount)
    {
        this.diginfo = diginfo;
        this.salt = salt;
        this.iterationcount = biginteger.valueof(iterationcount);
    }

    public digestinfo getmac()
    {
        return diginfo;
    }

    public byte[] getsalt()
    {
        return salt;
    }

    public biginteger getiterationcount()
    {
        return iterationcount;
    }

    /**
     * <pre>
     * macdata ::= sequence {
     *     mac      digestinfo,
     *     macsalt  octet string,
     *     iterations integer default 1
     *     -- note: the default is for historic reasons and its use is deprecated. a
     *     -- higher value, like 1024 is recommended.
     * </pre>
     * @return the basic asn1primitive construction.
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector  v = new asn1encodablevector();

        v.add(diginfo);
        v.add(new deroctetstring(salt));
        
        if (!iterationcount.equals(one))
        {
            v.add(new asn1integer(iterationcount));
        }

        return new dersequence(v);
    }
}
