package org.ripple.bouncycastle.asn1.x509;

import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dergeneralizedtime;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;

/**
 * <pre>
 *    privatekeyusageperiod ::= sequence {
 *      notbefore       [0]     generalizedtime optional,
 *      notafter        [1]     generalizedtime optional }
 * </pre>
 */
public class privatekeyusageperiod
    extends asn1object
{
    public static privatekeyusageperiod getinstance(object obj)
    {
        if (obj instanceof privatekeyusageperiod)
        {
            return (privatekeyusageperiod)obj;
        }

        if (obj != null)
        {
            return new privatekeyusageperiod(asn1sequence.getinstance(obj));
        }

        return null;
    }

    private dergeneralizedtime _notbefore, _notafter;

    private privatekeyusageperiod(asn1sequence seq)
    {
        enumeration en = seq.getobjects();
        while (en.hasmoreelements())
        {
            asn1taggedobject tobj = (asn1taggedobject)en.nextelement();

            if (tobj.gettagno() == 0)
            {
                _notbefore = dergeneralizedtime.getinstance(tobj, false);
            }
            else if (tobj.gettagno() == 1)
            {
                _notafter = dergeneralizedtime.getinstance(tobj, false);
            }
        }
    }

    public dergeneralizedtime getnotbefore()
    {
        return _notbefore;
    }

    public dergeneralizedtime getnotafter()
    {
        return _notafter;
    }

    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        if (_notbefore != null)
        {
            v.add(new dertaggedobject(false, 0, _notbefore));
        }
        if (_notafter != null)
        {
            v.add(new dertaggedobject(false, 1, _notafter));
        }

        return new dersequence(v);
    }
}
