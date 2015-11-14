package org.ripple.bouncycastle.asn1.ocsp;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dersequence;

public class responsebytes
    extends asn1object
{
    asn1objectidentifier    responsetype;
    asn1octetstring        response;

    public responsebytes(
        asn1objectidentifier responsetype,
        asn1octetstring     response)
    {
        this.responsetype = responsetype;
        this.response = response;
    }

    public responsebytes(
        asn1sequence    seq)
    {
        responsetype = (asn1objectidentifier)seq.getobjectat(0);
        response = (asn1octetstring)seq.getobjectat(1);
    }

    public static responsebytes getinstance(
        asn1taggedobject obj,
        boolean          explicit)
    {
        return getinstance(asn1sequence.getinstance(obj, explicit));
    }

    public static responsebytes getinstance(
        object  obj)
    {
        if (obj == null || obj instanceof responsebytes)
        {
            return (responsebytes)obj;
        }
        else if (obj instanceof asn1sequence)
        {
            return new responsebytes((asn1sequence)obj);
        }

        throw new illegalargumentexception("unknown object in factory: " + obj.getclass().getname());
    }

    public asn1objectidentifier getresponsetype()
    {
        return responsetype;
    }

    public asn1octetstring getresponse()
    {
        return response;
    }

    /**
     * produce an object suitable for an asn1outputstream.
     * <pre>
     * responsebytes ::=       sequence {
     *     responsetype   object identifier,
     *     response       octet string }
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector    v = new asn1encodablevector();

        v.add(responsetype);
        v.add(response);

        return new dersequence(v);
    }
}
