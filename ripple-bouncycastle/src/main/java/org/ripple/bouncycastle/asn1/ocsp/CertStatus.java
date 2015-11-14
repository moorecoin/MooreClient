package org.ripple.bouncycastle.asn1.ocsp;

import org.ripple.bouncycastle.asn1.asn1choice;
import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dernull;
import org.ripple.bouncycastle.asn1.dertaggedobject;

public class certstatus
    extends asn1object
    implements asn1choice
{
    private int             tagno;
    private asn1encodable    value;

    /**
     * create a certstatus object with a tag of zero.
     */
    public certstatus()
    {
        tagno = 0;
        value = dernull.instance;
    }

    public certstatus(
        revokedinfo info)
    {
        tagno = 1;
        value = info;
    }

    public certstatus(
        int tagno,
        asn1encodable    value)
    {
        this.tagno = tagno;
        this.value = value;
    }

    public certstatus(
        asn1taggedobject    choice)
    {
        this.tagno = choice.gettagno();

        switch (choice.gettagno())
        {
        case 0:
            value = dernull.instance;
            break;
        case 1:
            value = revokedinfo.getinstance(choice, false);
            break;
        case 2:
            value = dernull.instance;
        }
    }

    public static certstatus getinstance(
        object  obj)
    {
        if (obj == null || obj instanceof certstatus)
        {
            return (certstatus)obj;
        }
        else if (obj instanceof asn1taggedobject)
        {
            return new certstatus((asn1taggedobject)obj);
        }

        throw new illegalargumentexception("unknown object in factory: " + obj.getclass().getname());
    }

    public static certstatus getinstance(
        asn1taggedobject obj,
        boolean          explicit)
    {
        return getinstance(obj.getobject()); // must be explicitly tagged
    }
    
    public int gettagno()
    {
        return tagno;
    }

    public asn1encodable getstatus()
    {
        return value;
    }

    /**
     * produce an object suitable for an asn1outputstream.
     * <pre>
     *  certstatus ::= choice {
     *                  good        [0]     implicit null,
     *                  revoked     [1]     implicit revokedinfo,
     *                  unknown     [2]     implicit unknowninfo }
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        return new dertaggedobject(false, tagno, value);
    }
}
