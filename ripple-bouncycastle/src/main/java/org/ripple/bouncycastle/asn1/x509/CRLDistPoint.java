package org.ripple.bouncycastle.asn1.x509;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dersequence;

public class crldistpoint
    extends asn1object
{
    asn1sequence  seq = null;

    public static crldistpoint getinstance(
        asn1taggedobject obj,
        boolean          explicit)
    {
        return getinstance(asn1sequence.getinstance(obj, explicit));
    }

    public static crldistpoint getinstance(
        object  obj)
    {
        if (obj instanceof crldistpoint)
        {
            return (crldistpoint)obj;
        }
        else if (obj != null)
        {
            return new crldistpoint(asn1sequence.getinstance(obj));
        }

        return null;
    }

    private crldistpoint(
        asn1sequence seq)
    {
        this.seq = seq;
    }
    
    public crldistpoint(
        distributionpoint[] points)
    {
        asn1encodablevector  v = new asn1encodablevector();

        for (int i = 0; i != points.length; i++)
        {
            v.add(points[i]);
        }

        seq = new dersequence(v);
    }

    /**
     * return the distribution points making up the sequence.
     * 
     * @return distributionpoint[]
     */
    public distributionpoint[] getdistributionpoints()
    {
        distributionpoint[]    dp = new distributionpoint[seq.size()];
        
        for (int i = 0; i != seq.size(); i++)
        {
            dp[i] = distributionpoint.getinstance(seq.getobjectat(i));
        }
        
        return dp;
    }
    
    /**
     * produce an object suitable for an asn1outputstream.
     * <pre>
     * crldistpoint ::= sequence size {1..max} of distributionpoint
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        return seq;
    }

    public string tostring()
    {
        stringbuffer buf = new stringbuffer();
        string       sep = system.getproperty("line.separator");

        buf.append("crldistpoint:");
        buf.append(sep);
        distributionpoint dp[] = getdistributionpoints();
        for (int i = 0; i != dp.length; i++)
        {
            buf.append("    ");
            buf.append(dp[i]);
            buf.append(sep);
        }
        return buf.tostring();
    }
}
