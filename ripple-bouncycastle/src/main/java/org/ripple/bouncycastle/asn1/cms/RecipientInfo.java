package org.ripple.bouncycastle.asn1.cms;

import org.ripple.bouncycastle.asn1.asn1choice;
import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dertaggedobject;

public class recipientinfo
    extends asn1object
    implements asn1choice
{
    asn1encodable    info;

    public recipientinfo(
        keytransrecipientinfo info)
    {
        this.info = info;
    }

    public recipientinfo(
        keyagreerecipientinfo info)
    {
        this.info = new dertaggedobject(false, 1, info);
    }

    public recipientinfo(
        kekrecipientinfo info)
    {
        this.info = new dertaggedobject(false, 2, info);
    }

    public recipientinfo(
        passwordrecipientinfo info)
    {
        this.info = new dertaggedobject(false, 3, info);
    }

    public recipientinfo(
        otherrecipientinfo info)
    {
        this.info = new dertaggedobject(false, 4, info);
    }

    public recipientinfo(
        asn1primitive   info)
    {
        this.info = info;
    }

    public static recipientinfo getinstance(
        object  o)
    {
        if (o == null || o instanceof recipientinfo)
        {
            return (recipientinfo)o;
        }
        else if (o instanceof asn1sequence)
        {
            return new recipientinfo((asn1sequence)o);
        }
        else if (o instanceof asn1taggedobject)
        {
            return new recipientinfo((asn1taggedobject)o);
        }

        throw new illegalargumentexception("unknown object in factory: "
                                                    + o.getclass().getname());
    }

    public asn1integer getversion()
    {
        if (info instanceof asn1taggedobject)
        {
            asn1taggedobject o = (asn1taggedobject)info;

            switch (o.gettagno())
            {
            case 1:
                return keyagreerecipientinfo.getinstance(o, false).getversion();
            case 2:
                return getkekinfo(o).getversion();
            case 3:
                return passwordrecipientinfo.getinstance(o, false).getversion();
            case 4:
                return new asn1integer(0);    // no syntax version for otherrecipientinfo
            default:
                throw new illegalstateexception("unknown tag");
            }
        }

        return keytransrecipientinfo.getinstance(info).getversion();
    }

    public boolean istagged()
    {
        return (info instanceof asn1taggedobject);
    }

    public asn1encodable getinfo()
    {
        if (info instanceof asn1taggedobject)
        {
            asn1taggedobject o = (asn1taggedobject)info;

            switch (o.gettagno())
            {
            case 1:
                return keyagreerecipientinfo.getinstance(o, false);
            case 2:
                return getkekinfo(o);
            case 3:
                return passwordrecipientinfo.getinstance(o, false);
            case 4:
                return otherrecipientinfo.getinstance(o, false);
            default:
                throw new illegalstateexception("unknown tag");
            }
        }

        return keytransrecipientinfo.getinstance(info);
    }

    private kekrecipientinfo getkekinfo(asn1taggedobject o)
    {
        if (o.isexplicit())
        {                        // compatibilty with erroneous version
            return kekrecipientinfo.getinstance(o, true);
        }
        else
        {
            return kekrecipientinfo.getinstance(o, false);
        }
    }

    /**
     * produce an object suitable for an asn1outputstream.
     * <pre>
     * recipientinfo ::= choice {
     *     ktri keytransrecipientinfo,
     *     kari [1] keyagreerecipientinfo,
     *     kekri [2] kekrecipientinfo,
     *     pwri [3] passwordrecipientinfo,
     *     ori [4] otherrecipientinfo }
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        return info.toasn1primitive();
    }
}
