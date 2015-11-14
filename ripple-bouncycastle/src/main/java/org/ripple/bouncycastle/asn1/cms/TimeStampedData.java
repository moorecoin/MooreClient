package org.ripple.bouncycastle.asn1.cms;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.bersequence;
import org.ripple.bouncycastle.asn1.deria5string;

public class timestampeddata
    extends asn1object
{
    private asn1integer version;
    private deria5string datauri;
    private metadata metadata;
    private asn1octetstring content;
    private evidence temporalevidence;

    public timestampeddata(deria5string datauri, metadata metadata, asn1octetstring content, evidence temporalevidence)
    {
        this.version = new asn1integer(1);
        this.datauri = datauri;
        this.metadata = metadata;
        this.content = content;
        this.temporalevidence = temporalevidence;
    }

    private timestampeddata(asn1sequence seq)
    {
        this.version = asn1integer.getinstance(seq.getobjectat(0));

        int index = 1;
        if (seq.getobjectat(index) instanceof deria5string)
        {
            this.datauri = deria5string.getinstance(seq.getobjectat(index++));
        }
        if (seq.getobjectat(index) instanceof metadata || seq.getobjectat(index) instanceof asn1sequence)
        {
            this.metadata = metadata.getinstance(seq.getobjectat(index++));
        }
        if (seq.getobjectat(index) instanceof asn1octetstring)
        {
            this.content = asn1octetstring.getinstance(seq.getobjectat(index++));
        }
        this.temporalevidence = evidence.getinstance(seq.getobjectat(index));
    }

    public static timestampeddata getinstance(object obj)
    {
        if (obj instanceof timestampeddata)
        {
            return (timestampeddata)obj;
        }
        else if (obj != null)
        {
            return new timestampeddata(asn1sequence.getinstance(obj));
        }

        return null;
    }

    public deria5string getdatauri()
    {
        return datauri;
    }

    public metadata getmetadata()
    {
        return metadata;
    }

    public asn1octetstring getcontent()
    {
        return content;
    }

    public evidence gettemporalevidence()
    {
        return temporalevidence;
    }

    /**
     * <pre>
     * timestampeddata ::= sequence {
     *   version              integer { v1(1) },
     *   datauri              ia5string optional,
     *   metadata             metadata optional,
     *   content              octet string optional,
     *   temporalevidence     evidence
     * }
     * </pre>
     * @return
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        v.add(version);

        if (datauri != null)
        {
            v.add(datauri);
        }

        if (metadata != null)
        {
            v.add(metadata);
        }

        if (content != null)
        {
            v.add(content);
        }

        v.add(temporalevidence);

        return new bersequence(v);
    }
}
