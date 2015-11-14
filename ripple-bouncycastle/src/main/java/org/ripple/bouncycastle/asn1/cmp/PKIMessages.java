package org.ripple.bouncycastle.asn1.cmp;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;

public class pkimessages
    extends asn1object
{
    private asn1sequence content;

    private pkimessages(asn1sequence seq)
    {
        content = seq;
    }

    public static pkimessages getinstance(object o)
    {
        if (o instanceof pkimessages)
        {
            return (pkimessages)o;
        }

        if (o != null)
        {
            return new pkimessages(asn1sequence.getinstance(o));
        }

        return null;
    }

    public pkimessages(pkimessage msg)
    {
        content = new dersequence(msg);
    }

    public pkimessages(pkimessage[] msgs)
    {
        asn1encodablevector v = new asn1encodablevector();
        for (int i = 0; i < msgs.length; i++)
        {
            v.add(msgs[i]);
        }
        content = new dersequence(v);
    }

    public pkimessage[] topkimessagearray()
    {
        pkimessage[] result = new pkimessage[content.size()];

        for (int i = 0; i != result.length; i++)
        {
            result[i] = pkimessage.getinstance(content.getobjectat(i));
        }

        return result;
    }

    /**
     * <pre>
     * pkimessages ::= sequence size (1..max) of pkimessage
     * </pre>
     * @return a basic asn.1 object representation.
     */
    public asn1primitive toasn1primitive()
    {
        return content;
    }
}
