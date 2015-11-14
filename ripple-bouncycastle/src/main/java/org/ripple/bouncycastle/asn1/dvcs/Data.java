package org.ripple.bouncycastle.asn1.dvcs;

import org.ripple.bouncycastle.asn1.asn1choice;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.deroctetstring;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;
import org.ripple.bouncycastle.asn1.x509.digestinfo;

/**
 * <pre>
 * data ::= choice {
 *   message           octet string ,
 *   messageimprint    digestinfo,
 *   certs             [0] sequence size (1..max) of
 *                         targetetcchain
 * }
 * </pre>
 */

public class data
    extends asn1object
    implements asn1choice
{
    private asn1octetstring message;
    private digestinfo messageimprint;
    private asn1sequence certs;

    public data(byte[] messagebytes)
    {
        this.message = new deroctetstring(messagebytes);
    }

    public data(asn1octetstring message)
    {
        this.message = message;
    }

    public data(digestinfo messageimprint)
    {
        this.messageimprint = messageimprint;
    }

    public data(targetetcchain cert)
    {
        this.certs = new dersequence(cert);
    }

    public data(targetetcchain[] certs)
    {
        this.certs = new dersequence(certs);
    }

    private data(asn1sequence certs)
    {
        this.certs = certs;
    }

    public static data getinstance(object obj)
    {
        if (obj instanceof data)
        {
            return (data)obj;
        }
        else if (obj instanceof asn1octetstring)
        {
            return new data((asn1octetstring)obj);
        }
        else if (obj instanceof asn1sequence)
        {
            return new data(digestinfo.getinstance(obj));
        }
        else if (obj instanceof asn1taggedobject)
        {
            return new data(asn1sequence.getinstance((asn1taggedobject)obj, false));
        }
        throw new illegalargumentexception("unknown object submitted to getinstance: " + obj.getclass().getname());
    }

    public static data getinstance(
        asn1taggedobject obj,
        boolean explicit)
    {
        return getinstance(obj.getobject());
    }

    public asn1primitive toasn1primitive()
    {
        if (message != null)
        {
            return message.toasn1primitive();
        }
        if (messageimprint != null)
        {
            return messageimprint.toasn1primitive();
        }
        else
        {
            return new dertaggedobject(false, 0, certs);
        }
    }

    public string tostring()
    {
        if (message != null)
        {
            return "data {\n" + message + "}\n";
        }
        if (messageimprint != null)
        {
            return "data {\n" + messageimprint + "}\n";
        }
        else
        {
            return "data {\n" + certs + "}\n";
        }
    }

    public asn1octetstring getmessage()
    {
        return message;
    }

    public digestinfo getmessageimprint()
    {
        return messageimprint;
    }

    public targetetcchain[] getcerts()
    {
        if (certs == null)
        {
            return null;
        }

        targetetcchain[] tmp = new targetetcchain[certs.size()];

        for (int i = 0; i != tmp.length; i++)
        {
            tmp[i] = targetetcchain.getinstance(certs.getobjectat(i));
        }

        return tmp;
    }
}
