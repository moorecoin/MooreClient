package org.ripple.bouncycastle.asn1.pkcs;

import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.bersequence;
import org.ripple.bouncycastle.asn1.bertaggedobject;
import org.ripple.bouncycastle.asn1.dlsequence;

public class contentinfo
    extends asn1object
    implements pkcsobjectidentifiers
{
    private asn1objectidentifier contenttype;
    private asn1encodable content;
    private boolean       isber = true;

    public static contentinfo getinstance(
        object  obj)
    {
        if (obj instanceof contentinfo)
        {
            return (contentinfo)obj;
        }

        if (obj != null)
        {
            return new contentinfo(asn1sequence.getinstance(obj));
        }

        return null;
    }

    private contentinfo(
        asn1sequence  seq)
    {
        enumeration   e = seq.getobjects();

        contenttype = (asn1objectidentifier)e.nextelement();

        if (e.hasmoreelements())
        {
            content = ((asn1taggedobject)e.nextelement()).getobject();
        }

        isber = seq instanceof bersequence;
    }

    public contentinfo(
        asn1objectidentifier contenttype,
        asn1encodable content)
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
        asn1encodablevector v = new asn1encodablevector();

        v.add(contenttype);

        if (content != null)
        {
            v.add(new bertaggedobject(true, 0, content));
        }

        if (isber)
        {
            return new bersequence(v);
        }
        else
        {
            return new dlsequence(v);
        }
    }
}
