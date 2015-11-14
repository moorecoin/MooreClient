package org.ripple.bouncycastle.asn1.dvcs;

import java.math.biginteger;

import org.ripple.bouncycastle.asn1.asn1enumerated;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1taggedobject;


/**
 * servicetype ::= enumerated { cpd(1), vsd(2), cpkc(3), ccpd(4) }
 */

public class servicetype
    extends asn1object
{
    /**
     * identifier of cpd service (certify possession of data).
     */
    public static final servicetype cpd = new servicetype(1);

    /**
     * identifier of vsd service (verify signed document).
     */
    public static final servicetype vsd = new servicetype(2);

    /**
     * identifier of vpkc service (verify public key certificates (also referred to as cpkc)).
     */
    public static final servicetype vpkc = new servicetype(3);

    /**
     * identifier of ccpd service (certify claim of possession of data).
     */
    public static final servicetype ccpd = new servicetype(4);

    private asn1enumerated value;

    public servicetype(int value)
    {
        this.value = new asn1enumerated(value);
    }

    private servicetype(asn1enumerated value)
    {
        this.value = value;
    }

    public static servicetype getinstance(object obj)
    {
        if (obj instanceof servicetype)
        {
            return (servicetype)obj;
        }
        else if (obj != null)
        {
            return new servicetype(asn1enumerated.getinstance(obj));
        }

        return null;
    }

    public static servicetype getinstance(
        asn1taggedobject obj,
        boolean explicit)
    {
        return getinstance(asn1enumerated.getinstance(obj, explicit));
    }

    public biginteger getvalue()
    {
        return value.getvalue();
    }

    public asn1primitive toasn1primitive()
    {
        return value;
    }

    public string tostring()
    {
        int num = value.getvalue().intvalue();
        return "" + num + (
            num == cpd.getvalue().intvalue() ? "(cpd)" :
                num == vsd.getvalue().intvalue() ? "(vsd)" :
                    num == vpkc.getvalue().intvalue() ? "(vpkc)" :
                        num == ccpd.getvalue().intvalue() ? "(ccpd)" :
                            "?");
    }

}
