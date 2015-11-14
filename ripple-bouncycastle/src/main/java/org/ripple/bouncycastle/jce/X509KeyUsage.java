package org.ripple.bouncycastle.jce;

import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.x509.keyusage;

/**
 * a holding class for constructing an x509 key usage extension.
 *
 * <pre>
 *    id-ce-keyusage object identifier ::=  { id-ce 15 }
 *
 *    keyusage ::= bit string {
 *         digitalsignature        (0),
 *         nonrepudiation          (1),
 *         keyencipherment         (2),
 *         dataencipherment        (3),
 *         keyagreement            (4),
 *         keycertsign             (5),
 *         crlsign                 (6),
 *         encipheronly            (7),
 *         decipheronly            (8) }
 * </pre>
 */
public class x509keyusage
    extends asn1object
{
    public static final int        digitalsignature = 1 << 7; 
    public static final int        nonrepudiation   = 1 << 6;
    public static final int        keyencipherment  = 1 << 5;
    public static final int        dataencipherment = 1 << 4;
    public static final int        keyagreement     = 1 << 3;
    public static final int        keycertsign      = 1 << 2;
    public static final int        crlsign          = 1 << 1;
    public static final int        encipheronly     = 1 << 0;
    public static final int        decipheronly     = 1 << 15;

    private int usage = 0;

    /**
     * basic constructor.
     * 
     * @param usage - the bitwise or of the key usage flags giving the
     * allowed uses for the key.
     * e.g. (x509keyusage.keyencipherment | x509keyusage.dataencipherment)
     */
    public x509keyusage(
        int usage)
    {
        this.usage = usage;
    }

    public asn1primitive toasn1primitive()
    {
        return new keyusage(usage).toasn1primitive();
    }
}
