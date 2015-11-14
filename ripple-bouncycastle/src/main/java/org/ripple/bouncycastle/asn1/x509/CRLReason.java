package org.ripple.bouncycastle.asn1.x509;

import java.math.biginteger;
import java.util.hashtable;

import org.ripple.bouncycastle.asn1.asn1enumerated;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.util.integers;

/**
 * the crlreason enumeration.
 * <pre>
 * crlreason ::= enumerated {
 *  unspecified             (0),
 *  keycompromise           (1),
 *  cacompromise            (2),
 *  affiliationchanged      (3),
 *  superseded              (4),
 *  cessationofoperation    (5),
 *  certificatehold         (6),
 *  removefromcrl           (8),
 *  privilegewithdrawn      (9),
 *  aacompromise           (10)
 * }
 * </pre>
 */
public class crlreason
    extends asn1object
{
    /**
     * @deprecated use lower case version
     */
    public static final int unspecified = 0;
    /**
     * @deprecated use lower case version
     */
    public static final int key_compromise = 1;
    /**
     * @deprecated use lower case version
     */
    public static final int ca_compromise = 2;
    /**
     * @deprecated use lower case version
     */
    public static final int affiliation_changed = 3;
    /**
     * @deprecated use lower case version
     */
    public static final int superseded = 4;
    /**
     * @deprecated use lower case version
     */
    public static final int cessation_of_operation  = 5;
    /**
     * @deprecated use lower case version
     */
    public static final int certificate_hold = 6;
    /**
     * @deprecated use lower case version
     */
    public static final int remove_from_crl = 8;
    /**
     * @deprecated use lower case version
     */
    public static final int privilege_withdrawn = 9;
    /**
     * @deprecated use lower case version
     */
    public static final int aa_compromise = 10;

    public static final int unspecified = 0;
    public static final int keycompromise = 1;
    public static final int cacompromise = 2;
    public static final int affiliationchanged = 3;
    public static final int superseded = 4;
    public static final int cessationofoperation  = 5;
    public static final int certificatehold = 6;
    // 7 -> unknown
    public static final int removefromcrl = 8;
    public static final int privilegewithdrawn = 9;
    public static final int aacompromise = 10;

    private static final string[] reasonstring =
    {
        "unspecified", "keycompromise", "cacompromise", "affiliationchanged",
        "superseded", "cessationofoperation", "certificatehold", "unknown",
        "removefromcrl", "privilegewithdrawn", "aacompromise"
    };

    private static final hashtable table = new hashtable();

    private asn1enumerated value;

    public static crlreason getinstance(object o)
    {
        if (o instanceof crlreason)
        {
            return (crlreason)o;
        }
        else if (o != null)
        {
            return lookup(asn1enumerated.getinstance(o).getvalue().intvalue());
        }

        return null;
    }

    private crlreason(
        int reason)
    {
        value = new asn1enumerated(reason);
    }

    public string tostring()
    {
        string str;
        int reason = getvalue().intvalue();
        if (reason < 0 || reason > 10)
        {
            str = "invalid";
        }
        else
        {
            str = reasonstring[reason];
        }
        return "crlreason: " + str;
    }

    public biginteger getvalue()
    {
        return value.getvalue();
    }

    public asn1primitive toasn1primitive()
    {
        return value;
    }

    public static crlreason lookup(int value)
    {
        integer idx = integers.valueof(value);

        if (!table.containskey(idx))
        {
            table.put(idx, new crlreason(value));
        }

        return (crlreason)table.get(idx);
    }
}
