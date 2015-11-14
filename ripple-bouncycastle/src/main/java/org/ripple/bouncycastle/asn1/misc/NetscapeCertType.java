package org.ripple.bouncycastle.asn1.misc;

import org.ripple.bouncycastle.asn1.derbitstring;

/**
 * the netscapecerttype object.
 * <pre>
 *    netscapecerttype ::= bit string {
 *         sslclient               (0),
 *         sslserver               (1),
 *         s/mime                  (2),
 *         object signing          (3),
 *         reserved                (4),
 *         ssl ca                  (5),
 *         s/mime ca               (6),
 *         object signing ca       (7) }
 * </pre>
 */
public class netscapecerttype
    extends derbitstring
{
    public static final int        sslclient        = (1 << 7); 
    public static final int        sslserver        = (1 << 6);
    public static final int        smime            = (1 << 5);
    public static final int        objectsigning    = (1 << 4);
    public static final int        reserved         = (1 << 3);
    public static final int        sslca            = (1 << 2);
    public static final int        smimeca          = (1 << 1);
    public static final int        objectsigningca  = (1 << 0);

    /**
     * basic constructor.
     * 
     * @param usage - the bitwise or of the key usage flags giving the
     * allowed uses for the key.
     * e.g. (x509netscapecerttype.sslca | x509netscapecerttype.smimeca)
     */
    public netscapecerttype(
        int usage)
    {
        super(getbytes(usage), getpadbits(usage));
    }

    public netscapecerttype(
        derbitstring usage)
    {
        super(usage.getbytes(), usage.getpadbits());
    }

    public string tostring()
    {
        return "netscapecerttype: 0x" + integer.tohexstring(data[0] & 0xff);
    }
}
