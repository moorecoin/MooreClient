package org.ripple.bouncycastle.asn1.cms;

import org.ripple.bouncycastle.asn1.asn1choice;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dertaggedobject;

public class evidence
    extends asn1object
    implements asn1choice
{
    private timestamptokenevidence tstevidence;

    public evidence(timestamptokenevidence tstevidence)
    {
        this.tstevidence = tstevidence;
    }

    private evidence(asn1taggedobject tagged)
    {
        if (tagged.gettagno() == 0)
        {
            this.tstevidence = timestamptokenevidence.getinstance(tagged, false);
        }
    }

    public static evidence getinstance(object obj)
    {
        if (obj == null || obj instanceof evidence)
        {
            return (evidence)obj;
        }
        else if (obj instanceof asn1taggedobject)
        {
            return new evidence(asn1taggedobject.getinstance(obj));
        }

        throw new illegalargumentexception("unknown object in getinstance");
    }

    public timestamptokenevidence gettstevidence()
    {
        return tstevidence;
    }

    public asn1primitive toasn1primitive()
    {
       if (tstevidence != null)
       {
           return new dertaggedobject(false, 0, tstevidence);
       }

       return null;
    }
}
