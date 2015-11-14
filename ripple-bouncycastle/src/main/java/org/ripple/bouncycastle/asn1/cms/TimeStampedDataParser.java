package org.ripple.bouncycastle.asn1.cms;

import java.io.ioexception;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1octetstringparser;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1sequenceparser;
import org.ripple.bouncycastle.asn1.bersequence;
import org.ripple.bouncycastle.asn1.deria5string;

public class timestampeddataparser
{
    private asn1integer version;
    private deria5string datauri;
    private metadata metadata;
    private asn1octetstringparser content;
    private evidence temporalevidence;
    private asn1sequenceparser parser;

    private timestampeddataparser(asn1sequenceparser parser)
        throws ioexception
    {
        this.parser = parser;
        this.version = asn1integer.getinstance(parser.readobject());

        asn1encodable obj = parser.readobject();

        if (obj instanceof deria5string)
        {
            this.datauri = deria5string.getinstance(obj);
            obj = parser.readobject();
        }
        if (obj instanceof metadata || obj instanceof asn1sequenceparser)
        {
            this.metadata = metadata.getinstance(obj.toasn1primitive());
            obj = parser.readobject();
        }
        if (obj instanceof asn1octetstringparser)
        {
            this.content = (asn1octetstringparser)obj;
        }
    }

    public static timestampeddataparser getinstance(object obj)
        throws ioexception
    {
        if (obj instanceof asn1sequence)
        {
            return new timestampeddataparser(((asn1sequence)obj).parser());
        }
        if (obj instanceof asn1sequenceparser)
        {
            return new timestampeddataparser((asn1sequenceparser)obj);
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

    public asn1octetstringparser getcontent()
    {
        return content;
    }

    public evidence gettemporalevidence()
        throws ioexception
    {
        if (temporalevidence == null)
        {
            temporalevidence = evidence.getinstance(parser.readobject().toasn1primitive());
        }

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
     * @deprecated will be removed
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
