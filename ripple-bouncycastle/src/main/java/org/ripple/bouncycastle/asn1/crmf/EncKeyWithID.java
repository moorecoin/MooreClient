package org.ripple.bouncycastle.asn1.crmf;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.derutf8string;
import org.ripple.bouncycastle.asn1.pkcs.privatekeyinfo;
import org.ripple.bouncycastle.asn1.x509.generalname;

public class enckeywithid
    extends asn1object
{
    private final privatekeyinfo privkeyinfo;
    private final asn1encodable identifier;

    public static enckeywithid getinstance(object o)
    {
        if (o instanceof enckeywithid)
        {
            return (enckeywithid)o;
        }
        else if (o != null)
        {
            return new enckeywithid(asn1sequence.getinstance(o));
        }

        return null;
    }

    private enckeywithid(asn1sequence seq)
    {
        this.privkeyinfo = privatekeyinfo.getinstance(seq.getobjectat(0));

        if (seq.size() > 1)
        {
            if (!(seq.getobjectat(1) instanceof derutf8string))
            {
                this.identifier = generalname.getinstance(seq.getobjectat(1));
            }
            else
            {
                this.identifier = (asn1encodable)seq.getobjectat(1);
            }
        }
        else
        {
            this.identifier = null;
        }
    }

    public enckeywithid(privatekeyinfo privkeyinfo)
    {
        this.privkeyinfo = privkeyinfo;
        this.identifier = null;
    }

    public enckeywithid(privatekeyinfo privkeyinfo, derutf8string str)
    {
        this.privkeyinfo = privkeyinfo;
        this.identifier = str;
    }

    public enckeywithid(privatekeyinfo privkeyinfo, generalname generalname)
    {
        this.privkeyinfo = privkeyinfo;
        this.identifier = generalname;
    }

    public privatekeyinfo getprivatekey()
    {
        return privkeyinfo;
    }

    public boolean hasidentifier()
    {
        return identifier != null;
    }

    public boolean isidentifierutf8string()
    {
        return identifier instanceof derutf8string;
    }

    public asn1encodable getidentifier()
    {
        return identifier;
    }
    
    /**
     * <pre>
     * enckeywithid ::= sequence {
     *      privatekey           privatekeyinfo,
     *      identifier choice {
     *         string               utf8string,
     *         generalname          generalname
     *     } optional
     * }
     * </pre>
     * @return
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        v.add(privkeyinfo);

        if (identifier != null)
        {
            v.add(identifier);
        }

        return new dersequence(v);
    }
}
