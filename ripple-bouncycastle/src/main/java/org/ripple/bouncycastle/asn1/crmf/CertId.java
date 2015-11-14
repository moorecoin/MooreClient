package org.ripple.bouncycastle.asn1.crmf;

import java.math.biginteger;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.x509.generalname;

public class certid
    extends asn1object
{
    private generalname issuer;
    private asn1integer serialnumber;

    private certid(asn1sequence seq)
    {
        issuer = generalname.getinstance(seq.getobjectat(0));
        serialnumber = asn1integer.getinstance(seq.getobjectat(1));
    }

    public static certid getinstance(object o)
    {
        if (o instanceof certid)
        {
            return (certid)o;
        }

        if (o != null)
        {
            return new certid(asn1sequence.getinstance(o));
        }

        return null;
    }

    public static certid getinstance(asn1taggedobject obj, boolean isexplicit)
    {
        return getinstance(asn1sequence.getinstance(obj, isexplicit));
    }

    public certid(generalname issuer, biginteger serialnumber)
    {
        this(issuer, new asn1integer(serialnumber));
    }

    public certid(generalname issuer, asn1integer serialnumber)
    {
        this.issuer = issuer;
        this.serialnumber = serialnumber;
    }

    public generalname getissuer()
    {
        return issuer;
    }

    public asn1integer getserialnumber()
    {
        return serialnumber;
    }

    /**
     * <pre>
     * certid ::= sequence {
     *                 issuer           generalname,
     *                 serialnumber     integer }
     * </pre>
     * @return a basic asn.1 object representation.
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        v.add(issuer);
        v.add(serialnumber);
        
        return new dersequence(v);
    }
}
