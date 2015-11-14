package org.ripple.bouncycastle.asn1.dvcs;

import java.io.ioexception;

import org.ripple.bouncycastle.asn1.asn1choice;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dertaggedobject;

/**
 * <pre>
 *     dvcsresponse ::= choice
 *     {
 *         dvcertinfo         dvcscertinfo ,
 *         dverrornote        [0] dvcserrornotice
 *     }
 * </pre>
 */

public class dvcsresponse
    extends asn1object
    implements asn1choice
{
    private dvcscertinfo dvcertinfo;
    private dvcserrornotice dverrornote;

    public dvcsresponse(dvcscertinfo dvcertinfo)
    {
        this.dvcertinfo = dvcertinfo;
    }

    public dvcsresponse(dvcserrornotice dverrornote)
    {
        this.dverrornote = dverrornote;
    }

    public static dvcsresponse getinstance(object obj)
    {
        if (obj == null || obj instanceof dvcsresponse)
        {
            return (dvcsresponse)obj;
        }
        else
        {
            if (obj instanceof byte[])
            {
                try
                {
                    return getinstance(asn1primitive.frombytearray((byte[])obj));
                }
                catch (ioexception e)
                {
                    throw new illegalargumentexception("failed to construct sequence from byte[]: " + e.getmessage());
                }
            }
            if (obj instanceof asn1sequence)
            {
                dvcscertinfo dvcertinfo = dvcscertinfo.getinstance(obj);

                return new dvcsresponse(dvcertinfo);
            }
            if (obj instanceof asn1taggedobject)
            {
                asn1taggedobject t = asn1taggedobject.getinstance(obj);
                dvcserrornotice dverrornote = dvcserrornotice.getinstance(t, false);

                return new dvcsresponse(dverrornote);
            }
        }

        throw new illegalargumentexception("couldn't convert from object to dvcsresponse: " + obj.getclass().getname());
    }

    public static dvcsresponse getinstance(
        asn1taggedobject obj,
        boolean explicit)
    {
        return getinstance(asn1sequence.getinstance(obj, explicit));
    }

    public dvcscertinfo getcertinfo()
    {
        return dvcertinfo;
    }

    public dvcserrornotice geterrornotice()
    {
        return dverrornote;
    }

    public asn1primitive toasn1primitive()
    {
        if (dvcertinfo != null)
        {
            return dvcertinfo.toasn1primitive();
        }
        else
        {
            return new dertaggedobject(0, dverrornote);
        }
    }

    public string tostring()
    {
        if (dvcertinfo != null)
        {
            return "dvcsresponse {\ndvcertinfo: " + dvcertinfo.tostring() + "}\n";
        }
        if (dverrornote != null)
        {
            return "dvcsresponse {\ndverrornote: " + dverrornote.tostring() + "}\n";
        }
        return null;
    }
}
