package org.ripple.bouncycastle.asn1.x509;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1generalizedtime;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;

public class attcertvalidityperiod
    extends asn1object
{
    asn1generalizedtime  notbeforetime;
    asn1generalizedtime  notaftertime;

    public static attcertvalidityperiod getinstance(
            object  obj)
    {
        if (obj instanceof attcertvalidityperiod)
        {
            return (attcertvalidityperiod)obj;
        }
        else if (obj != null)
        {
            return new attcertvalidityperiod(asn1sequence.getinstance(obj));
        }
        
        return null;
    }
    
    private attcertvalidityperiod(
        asn1sequence    seq)
    {
        if (seq.size() != 2)
        {
            throw new illegalargumentexception("bad sequence size: "
                    + seq.size());
        }

        notbeforetime = asn1generalizedtime.getinstance(seq.getobjectat(0));
        notaftertime = asn1generalizedtime.getinstance(seq.getobjectat(1));
    }

    /**
     * @param notbeforetime
     * @param notaftertime
     */
    public attcertvalidityperiod(
        asn1generalizedtime notbeforetime,
        asn1generalizedtime notaftertime)
    {
        this.notbeforetime = notbeforetime;
        this.notaftertime = notaftertime;
    }

    public asn1generalizedtime getnotbeforetime()
    {
        return notbeforetime;
    }

    public asn1generalizedtime getnotaftertime()
    {
        return notaftertime;
    }

    /**
     * produce an object suitable for an asn1outputstream.
     * <pre>
     *  attcertvalidityperiod  ::= sequence {
     *       notbeforetime  generalizedtime,
     *       notaftertime   generalizedtime
     *  } 
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector  v = new asn1encodablevector();

        v.add(notbeforetime);
        v.add(notaftertime);

        return new dersequence(v);
    }
}
