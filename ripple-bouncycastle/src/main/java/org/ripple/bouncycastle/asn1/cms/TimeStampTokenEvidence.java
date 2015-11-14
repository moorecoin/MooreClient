package org.ripple.bouncycastle.asn1.cms;

import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dersequence;

public class timestamptokenevidence
    extends asn1object
{
    private timestampandcrl[] timestampandcrls;

    public timestamptokenevidence(timestampandcrl[] timestampandcrls)
    {
        this.timestampandcrls = timestampandcrls;
    }

    public timestamptokenevidence(timestampandcrl timestampandcrl)
    {
        this.timestampandcrls = new timestampandcrl[1];

        timestampandcrls[0] = timestampandcrl;
    }

    private timestamptokenevidence(asn1sequence seq)
    {
        this.timestampandcrls = new timestampandcrl[seq.size()];

        int count = 0;

        for (enumeration en = seq.getobjects(); en.hasmoreelements();)
        {
            timestampandcrls[count++] = timestampandcrl.getinstance(en.nextelement());
        }
    }

    public static timestamptokenevidence getinstance(asn1taggedobject tagged, boolean explicit)
    {
        return getinstance(asn1sequence.getinstance(tagged, explicit));
    }

    public static timestamptokenevidence getinstance(object obj)
    {
        if (obj instanceof timestamptokenevidence)
        {
            return (timestamptokenevidence)obj;
        }
        else if (obj != null)
        {
            return new timestamptokenevidence(asn1sequence.getinstance(obj));
        }

        return null;
    }

    public timestampandcrl[] totimestampandcrlarray()
    {
        return timestampandcrls;
    }
    
    /**
     * <pre>
     * timestamptokenevidence ::=
     *    sequence size(1..max) of timestampandcrl
     * </pre>
     * @return
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        for (int i = 0; i != timestampandcrls.length; i++)
        {
            v.add(timestampandcrls[i]);
        }

        return new dersequence(v);
    }

}
