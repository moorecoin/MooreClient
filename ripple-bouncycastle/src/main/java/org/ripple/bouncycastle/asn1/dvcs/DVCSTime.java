package org.ripple.bouncycastle.asn1.dvcs;

import java.util.date;

import org.ripple.bouncycastle.asn1.asn1choice;
import org.ripple.bouncycastle.asn1.asn1generalizedtime;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.cms.contentinfo;

/**
 * <pre>
 *     dvcstime ::= choice  {
 *         gentime                      generalizedtime,
 *         timestamptoken               contentinfo
 *     }
 * </pre>
 */
public class dvcstime
    extends asn1object
    implements asn1choice
{
    private asn1generalizedtime gentime;
    private contentinfo timestamptoken;
    private date time;

    // constructors:

    public dvcstime(date time)
    {
        this(new asn1generalizedtime(time));
    }

    public dvcstime(asn1generalizedtime gentime)
    {
        this.gentime = gentime;
    }

    public dvcstime(contentinfo timestamptoken)
    {
        this.timestamptoken = timestamptoken;
    }

    public static dvcstime getinstance(object obj)
    {
        if (obj instanceof dvcstime)
        {
            return (dvcstime)obj;
        }
        else if (obj instanceof asn1generalizedtime)
        {
            return new dvcstime(asn1generalizedtime.getinstance(obj));
        }
        else if (obj != null)
        {
            return new dvcstime(contentinfo.getinstance(obj));
        }

        return null;
    }

    public static dvcstime getinstance(
        asn1taggedobject obj,
        boolean explicit)
    {
        return getinstance(obj.getobject()); // must be explicitly tagged
    }


    // selectors:

    public asn1generalizedtime getgentime()
    {
        return gentime;
    }

    public contentinfo gettimestamptoken()
    {
        return timestamptoken;
    }

    public asn1primitive toasn1primitive()
    {

        if (gentime != null)
        {
            return gentime;
        }

        if (timestamptoken != null)
        {
            return timestamptoken.toasn1primitive();
        }

        return null;
    }

    public string tostring()
    {
        if (gentime != null)
        {
            return gentime.tostring();
        }
        if (timestamptoken != null)
        {
            return timestamptoken.tostring();
        }
        return null;
    }
}
