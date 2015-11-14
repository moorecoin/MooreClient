package org.ripple.bouncycastle.asn1.cmp;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;

public class certrepmessage
    extends asn1object
{
    private asn1sequence capubs;
    private asn1sequence response;

    private certrepmessage(asn1sequence seq)
    {
        int index = 0;

        if (seq.size() > 1)
        {
            capubs = asn1sequence.getinstance((asn1taggedobject)seq.getobjectat(index++), true);
        }

        response = asn1sequence.getinstance(seq.getobjectat(index));
    }

    public static certrepmessage getinstance(object o)
    {
        if (o instanceof certrepmessage)
        {
            return (certrepmessage)o;
        }

        if (o != null)
        {
            return new certrepmessage(asn1sequence.getinstance(o));
        }

        return null;
    }

    public certrepmessage(cmpcertificate[] capubs, certresponse[] response)
    {
        if (response == null)
        {
            throw new illegalargumentexception("'response' cannot be null");
        }

        if (capubs != null)
        {
            asn1encodablevector v = new asn1encodablevector();
            for (int i = 0; i < capubs.length; i++)
            {
                v.add(capubs[i]);
            }
            this.capubs = new dersequence(v);
        }

        {
            asn1encodablevector v = new asn1encodablevector();
            for (int i = 0; i < response.length; i++)
            {
                v.add(response[i]);
            }
            this.response = new dersequence(v);
        }
    }

    public cmpcertificate[] getcapubs()
    {
        if (capubs == null)
        {
            return null;
        }

        cmpcertificate[] results = new cmpcertificate[capubs.size()];

        for (int i = 0; i != results.length; i++)
        {
            results[i] = cmpcertificate.getinstance(capubs.getobjectat(i));
        }

        return results;
    }

    public certresponse[] getresponse()
    {
        certresponse[] results = new certresponse[response.size()];

        for (int i = 0; i != results.length; i++)
        {
            results[i] = certresponse.getinstance(response.getobjectat(i));
        }

        return results;
    }

    /**
     * <pre>
     * certrepmessage ::= sequence {
     *                          capubs       [1] sequence size (1..max) of cmpcertificate
     *                                                                             optional,
     *                          response         sequence of certresponse
     * }
     * </pre>
     * @return a basic asn.1 object representation.
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        if (capubs != null)
        {
            v.add(new dertaggedobject(true, 1, capubs));
        }

        v.add(response);

        return new dersequence(v);
    }
}
