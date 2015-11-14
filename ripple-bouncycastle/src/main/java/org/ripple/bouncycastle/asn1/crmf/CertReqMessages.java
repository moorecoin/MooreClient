package org.ripple.bouncycastle.asn1.crmf;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;

public class certreqmessages
    extends asn1object
{
    private asn1sequence content;

    private certreqmessages(asn1sequence seq)
    {
        content = seq;
    }

    public static certreqmessages getinstance(object o)
    {
        if (o instanceof certreqmessages)
        {
            return (certreqmessages)o;
        }

        if (o != null)
        {
            return new certreqmessages(asn1sequence.getinstance(o));
        }

        return null;
    }

    public certreqmessages(
        certreqmsg msg)
    {
        content = new dersequence(msg);
    }

    public certreqmessages(
        certreqmsg[] msgs)
    {
        asn1encodablevector v = new asn1encodablevector();
        for (int i = 0; i < msgs.length; i++)
        {
            v.add(msgs[i]);
        }
        content = new dersequence(v);
    }

    public certreqmsg[] tocertreqmsgarray()
    {
        certreqmsg[] result = new certreqmsg[content.size()];

        for (int i = 0; i != result.length; i++)
        {
            result[i] = certreqmsg.getinstance(content.getobjectat(i));
        }

        return result;
    }

    /**
     * <pre>
     * certreqmessages ::= sequence size (1..max) of certreqmsg
     * </pre>
     *
     * @return a basic asn.1 object representation.
     */
    public asn1primitive toasn1primitive()
    {
        return content;
    }
}
