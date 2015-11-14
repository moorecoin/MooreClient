package org.ripple.bouncycastle.asn1.tsp;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;


public class accuracy
    extends asn1object
{
    asn1integer seconds;

    asn1integer millis;

    asn1integer micros;

    // constantes
    protected static final int min_millis = 1;

    protected static final int max_millis = 999;

    protected static final int min_micros = 1;

    protected static final int max_micros = 999;

    protected accuracy()
    {
    }

    public accuracy(
        asn1integer seconds,
        asn1integer millis,
        asn1integer micros)
    {
        this.seconds = seconds;

        //verifications
        if (millis != null
                && (millis.getvalue().intvalue() < min_millis || millis
                        .getvalue().intvalue() > max_millis))
        {
            throw new illegalargumentexception(
                    "invalid millis field : not in (1..999)");
        }
        else
        {
            this.millis = millis;
        }

        if (micros != null
                && (micros.getvalue().intvalue() < min_micros || micros
                        .getvalue().intvalue() > max_micros))
        {
            throw new illegalargumentexception(
                    "invalid micros field : not in (1..999)");
        }
        else
        {
            this.micros = micros;
        }

    }

    private accuracy(asn1sequence seq)
    {
        seconds = null;
        millis = null;
        micros = null;

        for (int i = 0; i < seq.size(); i++)
        {
            // seconds
            if (seq.getobjectat(i) instanceof asn1integer)
            {
                seconds = (asn1integer) seq.getobjectat(i);
            }
            else if (seq.getobjectat(i) instanceof dertaggedobject)
            {
                dertaggedobject extra = (dertaggedobject) seq.getobjectat(i);

                switch (extra.gettagno())
                {
                case 0:
                    millis = asn1integer.getinstance(extra, false);
                    if (millis.getvalue().intvalue() < min_millis
                            || millis.getvalue().intvalue() > max_millis)
                    {
                        throw new illegalargumentexception(
                                "invalid millis field : not in (1..999).");
                    }
                    break;
                case 1:
                    micros = asn1integer.getinstance(extra, false);
                    if (micros.getvalue().intvalue() < min_micros
                            || micros.getvalue().intvalue() > max_micros)
                    {
                        throw new illegalargumentexception(
                                "invalid micros field : not in (1..999).");
                    }
                    break;
                default:
                    throw new illegalargumentexception("invalig tag number");
                }
            }
        }
    }

    public static accuracy getinstance(object o)
    {
        if (o instanceof accuracy)
        {
            return (accuracy) o;
        }

        if (o != null)
        {
            return new accuracy(asn1sequence.getinstance(o));
        }

        return null;
    }

    public asn1integer getseconds()
    {
        return seconds;
    }

    public asn1integer getmillis()
    {
        return millis;
    }

    public asn1integer getmicros()
    {
        return micros;
    }

    /**
     * <pre>
     * accuracy ::= sequence {
     *             seconds        integer              optional,
     *             millis     [0] integer  (1..999)    optional,
     *             micros     [1] integer  (1..999)    optional
     *             }
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {

        asn1encodablevector v = new asn1encodablevector();
        
        if (seconds != null)
        {
            v.add(seconds);
        }
        
        if (millis != null)
        {
            v.add(new dertaggedobject(false, 0, millis));
        }
        
        if (micros != null)
        {
            v.add(new dertaggedobject(false, 1, micros));
        }

        return new dersequence(v);
    }
}
