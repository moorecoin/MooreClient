package org.ripple.bouncycastle.asn1.cmp;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.deroctetstring;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;

public class pbmparameter
    extends asn1object
{
    private asn1octetstring salt;
    private algorithmidentifier owf;
    private asn1integer iterationcount;
    private algorithmidentifier mac;

    private pbmparameter(asn1sequence seq)
    {
        salt = asn1octetstring.getinstance(seq.getobjectat(0));
        owf = algorithmidentifier.getinstance(seq.getobjectat(1));
        iterationcount = asn1integer.getinstance(seq.getobjectat(2));
        mac = algorithmidentifier.getinstance(seq.getobjectat(3));
    }

    public static pbmparameter getinstance(object o)
    {
        if (o instanceof pbmparameter)
        {
            return (pbmparameter)o;
        }

        if (o != null)
        {
            return new pbmparameter(asn1sequence.getinstance(o));
        }

        return null;
    }

    public pbmparameter(
        byte[] salt,
        algorithmidentifier owf,
        int iterationcount,
        algorithmidentifier mac)
    {
        this(new deroctetstring(salt), owf,
             new asn1integer(iterationcount), mac);
    }

    public pbmparameter(
        asn1octetstring salt,
        algorithmidentifier owf,
        asn1integer iterationcount,
        algorithmidentifier mac)
    {
        this.salt = salt;
        this.owf = owf;
        this.iterationcount = iterationcount;
        this.mac = mac;
    }

    public asn1octetstring getsalt()
    {
        return salt;
    }

    public algorithmidentifier getowf()
    {
        return owf;
    }

    public asn1integer getiterationcount()
    {
        return iterationcount;
    }

    public algorithmidentifier getmac()
    {
        return mac;
    }

    /**
     * <pre>
     *  pbmparameter ::= sequence {
     *                        salt                octet string,
     *                        -- note:  implementations may wish to limit acceptable sizes
     *                        -- of this string to values appropriate for their environment
     *                        -- in order to reduce the risk of denial-of-service attacks
     *                        owf                 algorithmidentifier,
     *                        -- algid for a one-way function (sha-1 recommended)
     *                        iterationcount      integer,
     *                        -- number of times the owf is applied
     *                        -- note:  implementations may wish to limit acceptable sizes
     *                        -- of this integer to values appropriate for their environment
     *                        -- in order to reduce the risk of denial-of-service attacks
     *                        mac                 algorithmidentifier
     *                        -- the mac algid (e.g., des-mac, triple-des-mac [pkcs11],
     *    }   -- or hmac [rfc2104, rfc2202])
     * </pre>
     * @return a basic asn.1 object representation.
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        v.add(salt);
        v.add(owf);
        v.add(iterationcount);
        v.add(mac);
        
        return new dersequence(v);
    }
}
