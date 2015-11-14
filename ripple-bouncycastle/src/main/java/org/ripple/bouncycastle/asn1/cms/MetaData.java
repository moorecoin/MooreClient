package org.ripple.bouncycastle.asn1.cms;

import org.ripple.bouncycastle.asn1.asn1boolean;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.deria5string;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.derutf8string;

public class metadata
    extends asn1object
{
    private asn1boolean hashprotected;
    private derutf8string filename;
    private deria5string  mediatype;
    private attributes othermetadata;

    public metadata(
        asn1boolean hashprotected,
        derutf8string filename,
        deria5string mediatype,
        attributes othermetadata)
    {
        this.hashprotected = hashprotected;
        this.filename = filename;
        this.mediatype = mediatype;
        this.othermetadata = othermetadata;
    }

    private metadata(asn1sequence seq)
    {
        this.hashprotected = asn1boolean.getinstance(seq.getobjectat(0));

        int index = 1;

        if (index < seq.size() && seq.getobjectat(index) instanceof derutf8string)
        {
            this.filename = derutf8string.getinstance(seq.getobjectat(index++));
        }
        if (index < seq.size() && seq.getobjectat(index) instanceof deria5string)
        {
            this.mediatype = deria5string.getinstance(seq.getobjectat(index++));
        }
        if (index < seq.size())
        {
            this.othermetadata = attributes.getinstance(seq.getobjectat(index++));
        }
    }

    public static metadata getinstance(object obj)
    {
        if (obj instanceof metadata)
        {
            return (metadata)obj;
        }
        else if (obj != null)
        {
            return new metadata(asn1sequence.getinstance(obj));
        }

        return null;
    }

    /**
     * <pre>
     * metadata ::= sequence {
     *   hashprotected        boolean,
     *   filename             utf8string optional,
     *   mediatype            ia5string optional,
     *   othermetadata        attributes optional
     * }
     * </pre>
     * @return
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        v.add(hashprotected);

        if (filename != null)
        {
            v.add(filename);
        }

        if (mediatype != null)
        {
            v.add(mediatype);
        }

        if (othermetadata != null)
        {
            v.add(othermetadata);
        }
        
        return new dersequence(v);
    }

    public boolean ishashprotected()
    {
        return hashprotected.istrue();
    }

    public derutf8string getfilename()
    {
        return this.filename;
    }

    public deria5string getmediatype()
    {
        return this.mediatype;
    }

    public attributes getothermetadata()
    {
        return othermetadata;
    }
}
