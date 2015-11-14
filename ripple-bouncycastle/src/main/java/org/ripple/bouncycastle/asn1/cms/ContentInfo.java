package org.ripple.bouncycastle.asn1.cms;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.bersequence;
import org.ripple.bouncycastle.asn1.bertaggedobject;

public class contentinfo
    extends asn1object
    implements cmsobjectidentifiers
{
    private asn1objectidentifier contenttype;
    private asn1encodable        content;

    public static contentinfo getinstance(
        object  obj)
    {
        if (obj instanceof contentinfo)
        {
            return (contentinfo)obj;
        }
        else if (obj != null)
        {
            return new contentinfo(asn1sequence.getinstance(obj));
        }

        return null;
    }

    public static contentinfo getinstance(
        asn1taggedobject obj,
        boolean explicit)
    {
        return getinstance(asn1sequence.getinstance(obj, explicit));
    }

    /**
     * @deprecated use getinstance()
     */
    public contentinfo(
        asn1sequence  seq)
    {
        if (seq.size() < 1 || seq.size() > 2)
        {
            throw new illegalargumentexception("bad sequence size: " + seq.size());
        }

        contenttype = (asn1objectidentifier)seq.getobjectat(0);

        if (seq.size() > 1)
        {
            asn1taggedobject tagged = (asn1taggedobject)seq.getobjectat(1);
            if (!tagged.isexplicit() || tagged.gettagno() != 0)
            {
                throw new illegalargumentexception("bad tag for 'content'");
            }

            content = tagged.getobject();
        }
    }

    public contentinfo(
        asn1objectidentifier contenttype,
        asn1encodable        content)
    {
        this.contenttype = contenttype;
        this.content = content;
    }

    public asn1objectidentifier getcontenttype()
    {
        return contenttype;
    }

    public asn1encodable getcontent()
    {
        return content;
    }

    /**
     * produce an object suitable for an asn1outputstream.
     * <pre>
     * contentinfo ::= sequence {
     *          contenttype contenttype,
     *          content
     *          [0] explicit any defined by contenttype optional }
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector  v = new asn1encodablevector();

        v.add(contenttype);

        if (content != null)
        {
            v.add(new bertaggedobject(0, content));
        }

        return new bersequence(v);
    }
}
