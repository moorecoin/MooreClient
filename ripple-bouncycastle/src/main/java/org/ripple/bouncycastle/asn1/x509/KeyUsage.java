package org.ripple.bouncycastle.asn1.x509;

import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.derbitstring;

/**
 * the keyusage object.
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
public class keyusage
    extends asn1object
{
    public static final int        digitalsignature = (1 << 7); 
    public static final int        nonrepudiation   = (1 << 6);
    public static final int        keyencipherment  = (1 << 5);
    public static final int        dataencipherment = (1 << 4);
    public static final int        keyagreement     = (1 << 3);
    public static final int        keycertsign      = (1 << 2);
    public static final int        crlsign          = (1 << 1);
    public static final int        encipheronly     = (1 << 0);
    public static final int        decipheronly     = (1 << 15);

    private derbitstring bitstring;

    public static keyusage getinstance(object obj)   // needs to be derbitstring for other vms
    {
        if (obj instanceof keyusage)
        {
            return (keyusage)obj;
        }
        else if (obj != null)
        {
            return new keyusage(derbitstring.getinstance(obj));
        }

        return null;
    }

    public static keyusage fromextensions(extensions extensions)
    {
        return keyusage.getinstance(extensions.getextensionparsedvalue(extension.keyusage));
    }

    /**
     * basic constructor.
     * 
     * @param usage - the bitwise or of the key usage flags giving the
     * allowed uses for the key.
     * e.g. (keyusage.keyencipherment | keyusage.dataencipherment)
     */
    public keyusage(
        int usage)
    {
        this.bitstring = new derbitstring(usage);
    }

    private keyusage(
        derbitstring bitstring)
    {
        this.bitstring = bitstring;
    }

    public byte[] getbytes()
    {
        return bitstring.getbytes();
    }

    public int getpadbits()
    {
        return bitstring.getpadbits();
    }

    public string tostring()
    {
        byte[] data = bitstring.getbytes();

        if (data.length == 1)
        {
            return "keyusage: 0x" + integer.tohexstring(data[0] & 0xff);
        }
        return "keyusage: 0x" + integer.tohexstring((data[1] & 0xff) << 8 | (data[0] & 0xff));
    }

    public asn1primitive toasn1primitive()
    {
        return bitstring;
    }
}
