package org.ripple.bouncycastle.asn1.x509;

import org.ripple.bouncycastle.asn1.derbitstring;

/**
 * the reasonflags object.
 * <pre>
 * reasonflags ::= bit string {
 *      unused                  (0),
 *      keycompromise           (1),
 *      cacompromise            (2),
 *      affiliationchanged      (3),
 *      superseded              (4),
 *      cessationofoperation    (5),
 *      certificatehold         (6),
 *      privilegewithdrawn      (7),
 *      aacompromise            (8) }
 * </pre>
 */
public class reasonflags
    extends derbitstring
{
    /**
     * @deprecated use lower case version
     */
    public static final int unused                  = (1 << 7);
    /**
     * @deprecated use lower case version
     */
    public static final int key_compromise          = (1 << 6);
    /**
     * @deprecated use lower case version
     */
    public static final int ca_compromise           = (1 << 5);
    /**
     * @deprecated use lower case version
     */
    public static final int affiliation_changed     = (1 << 4);
    /**
     * @deprecated use lower case version
     */
    public static final int superseded              = (1 << 3);
    /**
     * @deprecated use lower case version
     */
    public static final int cessation_of_operation  = (1 << 2);
    /**
     * @deprecated use lower case version
     */
    public static final int certificate_hold        = (1 << 1);
    /**
     * @deprecated use lower case version
     */
    public static final int privilege_withdrawn     = (1 << 0);
    /**
     * @deprecated use lower case version
     */
    public static final int aa_compromise           = (1 << 15);
    
    public static final int unused                  = (1 << 7);
    public static final int keycompromise           = (1 << 6);
    public static final int cacompromise            = (1 << 5);
    public static final int affiliationchanged      = (1 << 4);
    public static final int superseded              = (1 << 3);
    public static final int cessationofoperation    = (1 << 2);
    public static final int certificatehold         = (1 << 1);
    public static final int privilegewithdrawn      = (1 << 0);
    public static final int aacompromise            = (1 << 15);

    /**
     * @param reasons - the bitwise or of the key reason flags giving the
     * allowed uses for the key.
     */
    public reasonflags(
        int reasons)
    {
        super(getbytes(reasons), getpadbits(reasons));
    }

    public reasonflags(
        derbitstring reasons)
    {
        super(reasons.getbytes(), reasons.getpadbits());
    }
}
