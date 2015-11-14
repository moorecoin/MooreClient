package org.ripple.bouncycastle.asn1.x509;

import java.math.biginteger;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.derbitstring;
import org.ripple.bouncycastle.asn1.dersequence;

public class issuerserial
    extends asn1object
{
    generalnames            issuer;
    asn1integer              serial;
    derbitstring            issueruid;

    public static issuerserial getinstance(
            object  obj)
    {
        if (obj instanceof issuerserial)
        {
            return (issuerserial)obj;
        }

        if (obj != null)
        {
            return new issuerserial(asn1sequence.getinstance(obj));
        }

        return null;
    }

    public static issuerserial getinstance(
        asn1taggedobject obj,
        boolean          explicit)
    {
        return getinstance(asn1sequence.getinstance(obj, explicit));
    }
    
    private issuerserial(
        asn1sequence    seq)
    {
        if (seq.size() != 2 && seq.size() != 3)
        {
            throw new illegalargumentexception("bad sequence size: " + seq.size());
        }
        
        issuer = generalnames.getinstance(seq.getobjectat(0));
        serial = asn1integer.getinstance(seq.getobjectat(1));

        if (seq.size() == 3)
        {
            issueruid = derbitstring.getinstance(seq.getobjectat(2));
        }
    }

    public issuerserial(
        generalnames    issuer,
        biginteger serial)
    {
        this(issuer, new asn1integer(serial));
    }

    public issuerserial(
        generalnames    issuer,
        asn1integer      serial)
    {
        this.issuer = issuer;
        this.serial = serial;
    }

    public generalnames getissuer()
    {
        return issuer;
    }

    public asn1integer getserial()
    {
        return serial;
    }

    public derbitstring getissueruid()
    {
        return issueruid;
    }

    /**
     * produce an object suitable for an asn1outputstream.
     * <pre>
     *  issuerserial  ::=  sequence {
     *       issuer         generalnames,
     *       serial         certificateserialnumber,
     *       issueruid      uniqueidentifier optional
     *  }
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector  v = new asn1encodablevector();

        v.add(issuer);
        v.add(serial);

        if (issueruid != null)
        {
            v.add(issueruid);
        }

        return new dersequence(v);
    }
}
