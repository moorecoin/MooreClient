package org.ripple.bouncycastle.asn1.x509;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.derbitstring;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;

/**
 * the distributionpoint object.
 * <pre>
 * distributionpoint ::= sequence {
 *      distributionpoint [0] distributionpointname optional,
 *      reasons           [1] reasonflags optional,
 *      crlissuer         [2] generalnames optional
 * }
 * </pre>
 */
public class distributionpoint
    extends asn1object
{
    distributionpointname       distributionpoint;
    reasonflags                 reasons;
    generalnames                crlissuer;

    public static distributionpoint getinstance(
        asn1taggedobject obj,
        boolean          explicit)
    {
        return getinstance(asn1sequence.getinstance(obj, explicit));
    }

    public static distributionpoint getinstance(
        object obj)
    {
        if(obj == null || obj instanceof distributionpoint) 
        {
            return (distributionpoint)obj;
        }
        
        if(obj instanceof asn1sequence) 
        {
            return new distributionpoint((asn1sequence)obj);
        }
        
        throw new illegalargumentexception("invalid distributionpoint: " + obj.getclass().getname());
    }

    public distributionpoint(
        asn1sequence seq)
    {
        for (int i = 0; i != seq.size(); i++)
        {
            asn1taggedobject    t = asn1taggedobject.getinstance(seq.getobjectat(i));
            switch (t.gettagno())
            {
            case 0:
                distributionpoint = distributionpointname.getinstance(t, true);
                break;
            case 1:
                reasons = new reasonflags(derbitstring.getinstance(t, false));
                break;
            case 2:
                crlissuer = generalnames.getinstance(t, false);
            }
        }
    }
    
    public distributionpoint(
        distributionpointname distributionpoint,
        reasonflags                 reasons,
        generalnames            crlissuer)
    {
        this.distributionpoint = distributionpoint;
        this.reasons = reasons;
        this.crlissuer = crlissuer;
    }
    
    public distributionpointname getdistributionpoint()
    {
        return distributionpoint;
    }

    public reasonflags getreasons()
    {
        return reasons;
    }
    
    public generalnames getcrlissuer()
    {
        return crlissuer;
    }
    
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector  v = new asn1encodablevector();
        
        if (distributionpoint != null)
        {
            //
            // as this is a choice it must be explicitly tagged
            //
            v.add(new dertaggedobject(0, distributionpoint));
        }

        if (reasons != null)
        {
            v.add(new dertaggedobject(false, 1, reasons));
        }

        if (crlissuer != null)
        {
            v.add(new dertaggedobject(false, 2, crlissuer));
        }

        return new dersequence(v);
    }

    public string tostring()
    {
        string       sep = system.getproperty("line.separator");
        stringbuffer buf = new stringbuffer();
        buf.append("distributionpoint: [");
        buf.append(sep);
        if (distributionpoint != null)
        {
            appendobject(buf, sep, "distributionpoint", distributionpoint.tostring());
        }
        if (reasons != null)
        {
            appendobject(buf, sep, "reasons", reasons.tostring());
        }
        if (crlissuer != null)
        {
            appendobject(buf, sep, "crlissuer", crlissuer.tostring());
        }
        buf.append("]");
        buf.append(sep);
        return buf.tostring();
    }

    private void appendobject(stringbuffer buf, string sep, string name, string value)
    {
        string       indent = "    ";

        buf.append(indent);
        buf.append(name);
        buf.append(":");
        buf.append(sep);
        buf.append(indent);
        buf.append(indent);
        buf.append(value);
        buf.append(sep);
    }
}
