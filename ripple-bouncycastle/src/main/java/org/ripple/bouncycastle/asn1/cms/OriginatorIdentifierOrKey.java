package org.ripple.bouncycastle.asn1.cms;

import org.ripple.bouncycastle.asn1.asn1choice;
import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dertaggedobject;
import org.ripple.bouncycastle.asn1.x509.subjectkeyidentifier;

public class originatoridentifierorkey
    extends asn1object
    implements asn1choice
{
    private asn1encodable id;

    public originatoridentifierorkey(
        issuerandserialnumber id)
    {
        this.id = id;
    }

    /**
     * @deprecated use version taking a subjectkeyidentifier
     */
    public originatoridentifierorkey(
        asn1octetstring id)
    {
        this(new subjectkeyidentifier(id.getoctets()));
    }

    public originatoridentifierorkey(
        subjectkeyidentifier id)
    {
        this.id = new dertaggedobject(false, 0, id);
    }

    public originatoridentifierorkey(
        originatorpublickey id)
    {
        this.id = new dertaggedobject(false, 1, id);
    }

    /**
     * @deprecated use more specific version
     */
    public originatoridentifierorkey(
        asn1primitive id)
    {
        this.id = id;
    }

    /**
     * return an originatoridentifierorkey object from a tagged object.
     *
     * @param o the tagged object holding the object we want.
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception illegalargumentexception if the object held by the
     *          tagged object cannot be converted.
     */
    public static originatoridentifierorkey getinstance(
        asn1taggedobject    o,
        boolean             explicit)
    {
        if (!explicit)
        {
            throw new illegalargumentexception(
                    "can't implicitly tag originatoridentifierorkey");
        }

        return getinstance(o.getobject());
    }
    
    /**
     * return an originatoridentifierorkey object from the given object.
     *
     * @param o the object we want converted.
     * @exception illegalargumentexception if the object cannot be converted.
     */
    public static originatoridentifierorkey getinstance(
        object o)
    {
        if (o == null || o instanceof originatoridentifierorkey)
        {
            return (originatoridentifierorkey)o;
        }

        if (o instanceof issuerandserialnumber)
        {
            return new originatoridentifierorkey((issuerandserialnumber)o);
        }

        if (o instanceof subjectkeyidentifier)
        {
            return new originatoridentifierorkey((subjectkeyidentifier)o);
        }

        if (o instanceof originatorpublickey)
        {
            return new originatoridentifierorkey((originatorpublickey)o);
        }

        if (o instanceof asn1taggedobject)
        {
            // todo add validation
            return new originatoridentifierorkey((asn1taggedobject)o);
        }

        throw new illegalargumentexception("invalid originatoridentifierorkey: " + o.getclass().getname());
    }

    public asn1encodable getid()
    {
        return id;
    }

    public issuerandserialnumber getissuerandserialnumber()
    {
        if (id instanceof issuerandserialnumber)
        {
            return (issuerandserialnumber)id;
        }

        return null;
    }

    public subjectkeyidentifier getsubjectkeyidentifier()
    {
        if (id instanceof asn1taggedobject && ((asn1taggedobject)id).gettagno() == 0)
        {
            return subjectkeyidentifier.getinstance((asn1taggedobject)id, false);
        }

        return null;
    }

    public originatorpublickey getoriginatorkey()
    {
        if (id instanceof asn1taggedobject && ((asn1taggedobject)id).gettagno() == 1)
        {
            return originatorpublickey.getinstance((asn1taggedobject)id, false);
        }

        return null;
    }

    /**
     * produce an object suitable for an asn1outputstream.
     * <pre>
     * originatoridentifierorkey ::= choice {
     *     issuerandserialnumber issuerandserialnumber,
     *     subjectkeyidentifier [0] subjectkeyidentifier,
     *     originatorkey [1] originatorpublickey 
     * }
     *
     * subjectkeyidentifier ::= octet string
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        return id.toasn1primitive();
    }
}
