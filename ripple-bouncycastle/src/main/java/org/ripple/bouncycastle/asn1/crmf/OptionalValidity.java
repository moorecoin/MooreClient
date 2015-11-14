package org.ripple.bouncycastle.asn1.crmf;

import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;
import org.ripple.bouncycastle.asn1.x509.time;

public class optionalvalidity
    extends asn1object
{
    private time notbefore;
    private time notafter;

    private optionalvalidity(asn1sequence seq)
    {
        enumeration en = seq.getobjects();
        while (en.hasmoreelements())
        {
            asn1taggedobject tobj = (asn1taggedobject)en.nextelement();

            if (tobj.gettagno() == 0)
            {
                notbefore = time.getinstance(tobj, true);
            }
            else
            {
                notafter = time.getinstance(tobj, true);
            }
        }
    }

    public static optionalvalidity getinstance(object o)
    {
        if (o instanceof optionalvalidity)
        {
            return (optionalvalidity)o;
        }

        if (o != null)
        {
            return new optionalvalidity(asn1sequence.getinstance(o));
        }

        return null;
    }

    public optionalvalidity(time notbefore, time notafter)
    {
        if (notbefore == null && notafter == null)
        {
            throw new illegalargumentexception("at least one of notbefore/notafter must not be null.");
        }

        this.notbefore = notbefore;
        this.notafter = notafter;
    }

    public time getnotbefore()
    {
        return notbefore;
    }

    public time getnotafter()
    {
        return notafter;
    }

    /**
     * <pre>
     * optionalvalidity ::= sequence {
     *                        notbefore  [0] time optional,
     *                        notafter   [1] time optional } --at least one must be present
     * </pre>
     * @return a basic asn.1 object representation.
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        if (notbefore != null)
        {
            v.add(new dertaggedobject(true, 0, notbefore));
        }

        if (notafter != null)
        {
            v.add(new dertaggedobject(true, 1, notafter));
        }

        return new dersequence(v);
    }
}
