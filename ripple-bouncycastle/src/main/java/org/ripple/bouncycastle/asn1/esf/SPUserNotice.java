package org.ripple.bouncycastle.asn1.esf;

import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1string;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.x509.displaytext;
import org.ripple.bouncycastle.asn1.x509.noticereference;

public class spusernotice
    extends asn1object
{
    private noticereference noticeref;
    private displaytext     explicittext;

    public static spusernotice getinstance(
        object obj)
    {
        if (obj instanceof spusernotice)
        {
            return (spusernotice)obj;
        }
        else if (obj != null)
        {
            return new spusernotice(asn1sequence.getinstance(obj));
        }

        return null;
    }

    private spusernotice(
        asn1sequence seq)
    {
        enumeration e = seq.getobjects();
        while (e.hasmoreelements())
        {
            asn1encodable object = (asn1encodable)e.nextelement();
            if (object instanceof displaytext || object instanceof asn1string)
            {
                explicittext = displaytext.getinstance(object);
            }
            else if (object instanceof noticereference || object instanceof asn1sequence)
            {
                noticeref = noticereference.getinstance(object);
            }
            else
            {
                throw new illegalargumentexception("invalid element in 'spusernotice': " + object.getclass().getname());
            }
        }
    }

    public spusernotice(
        noticereference noticeref,
        displaytext     explicittext)
    {
        this.noticeref = noticeref;
        this.explicittext = explicittext;
    }

    public noticereference getnoticeref()
    {
        return noticeref;
    }

    public displaytext getexplicittext()
    {
        return explicittext;
    }

    /**
     * <pre>
     * spusernotice ::= sequence {
     *     noticeref noticereference optional,
     *     explicittext displaytext optional }
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector  v = new asn1encodablevector();

        if (noticeref != null)
        {
            v.add(noticeref);
        }

        if (explicittext != null)
        {
            v.add(explicittext);
        }

        return new dersequence(v);
    }
}
