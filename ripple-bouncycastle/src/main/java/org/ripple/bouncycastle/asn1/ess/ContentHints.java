package org.ripple.bouncycastle.asn1.ess;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.derobjectidentifier;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.derutf8string;

public class contenthints
    extends asn1object
{
    private derutf8string contentdescription;
    private asn1objectidentifier contenttype;

    public static contenthints getinstance(object o)
    {
        if (o instanceof contenthints)
        {
            return (contenthints)o;
        }
        else if (o != null)
        {
            return new contenthints(asn1sequence.getinstance(o));
        }

        return null;
    }

    /**
     * constructor
     */
    private contenthints(asn1sequence seq)
    {
        asn1encodable field = seq.getobjectat(0);
        if (field.toasn1primitive() instanceof derutf8string)
        {
            contentdescription = derutf8string.getinstance(field);
            contenttype = asn1objectidentifier.getinstance(seq.getobjectat(1));
        }
        else
        {
            contenttype = asn1objectidentifier.getinstance(seq.getobjectat(0));
        }
    }

    /**
     * @deprecated use asn1objectidentifier
     */
    public contenthints(
        derobjectidentifier contenttype)
    {
        this(new asn1objectidentifier(contenttype.getid()));
    }

        /**
     * @deprecated use asn1objectidentifier
     */
    public contenthints(
        derobjectidentifier contenttype,
        derutf8string contentdescription)
    {
        this(new asn1objectidentifier(contenttype.getid()), contentdescription);
    }

    public contenthints(
        asn1objectidentifier contenttype)
    {
        this.contenttype = contenttype;
        this.contentdescription = null;
    }

    public contenthints(
        asn1objectidentifier contenttype,
        derutf8string contentdescription)
    {
        this.contenttype = contenttype;
        this.contentdescription = contentdescription;
    }

    public asn1objectidentifier getcontenttype()
    {
        return contenttype;
    }

    public derutf8string getcontentdescription()
    {
        return contentdescription;
    }

    /**
     * <pre>
     * contenthints ::= sequence {
     *   contentdescription utf8string (size (1..max)) optional,
     *   contenttype contenttype }
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        if (contentdescription != null)
        {
            v.add(contentdescription);
        }

        v.add(contenttype);

        return new dersequence(v);
    }
}
