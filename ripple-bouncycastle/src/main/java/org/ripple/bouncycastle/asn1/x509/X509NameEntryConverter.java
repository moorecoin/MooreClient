package org.ripple.bouncycastle.asn1.x509;

import java.io.ioexception;

import org.ripple.bouncycastle.asn1.asn1inputstream;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.derprintablestring;
import org.ripple.bouncycastle.util.strings;

/**
 * it turns out that the number of standard ways the fields in a dn should be 
 * encoded into their asn.1 counterparts is rapidly approaching the
 * number of machines on the internet. by default the x509name class 
 * will produce utf8strings in line with the current recommendations (rfc 3280).
 * <p>
 * an example of an encoder look like below:
 * <pre>
 * public class x509direntryconverter
 *     extends x509nameentryconverter
 * {
 *     public asn1primitive getconvertedvalue(
 *         asn1objectidentifier  oid,
 *         string               value)
 *     {
 *         if (str.length() != 0 && str.charat(0) == '#')
 *         {
 *             return converthexencoded(str, 1);
 *         }
 *         if (oid.equals(emailaddress))
 *         {
 *             return new deria5string(str);
 *         }
 *         else if (canbeprintable(str))
 *         {
 *             return new derprintablestring(str);
 *         }
 *         else if (canbeutf8(str))
 *         {
 *             return new derutf8string(str);
 *         }
 *         else
 *         {
 *             return new derbmpstring(str);
 *         }
 *     }
 * }
 */
public abstract class x509nameentryconverter
{
    /**
     * convert an inline encoded hex string rendition of an asn.1
     * object back into its corresponding asn.1 object.
     * 
     * @param str the hex encoded object
     * @param off the index at which the encoding starts
     * @return the decoded object
     */
    protected asn1primitive converthexencoded(
        string  str,
        int     off)
        throws ioexception
    {
        str = strings.tolowercase(str);
        byte[] data = new byte[(str.length() - off) / 2];
        for (int index = 0; index != data.length; index++)
        {
            char left = str.charat((index * 2) + off);
            char right = str.charat((index * 2) + off + 1);
            
            if (left < 'a')
            {
                data[index] = (byte)((left - '0') << 4);
            }
            else
            {
                data[index] = (byte)((left - 'a' + 10) << 4);
            }
            if (right < 'a')
            {
                data[index] |= (byte)(right - '0');
            }
            else
            {
                data[index] |= (byte)(right - 'a' + 10);
            }
        }

        asn1inputstream ain = new asn1inputstream(data);
                                            
        return ain.readobject();
    }
    
    /**
     * return true if the passed in string can be represented without
     * loss as a printablestring, false otherwise.
     */
    protected boolean canbeprintable(
        string  str)
    {
        return derprintablestring.isprintablestring(str);
    }
    
    /**
     * convert the passed in string value into the appropriate asn.1
     * encoded object.
     * 
     * @param oid the oid associated with the value in the dn.
     * @param value the value of the particular dn component.
     * @return the asn.1 equivalent for the value.
     */
    public abstract asn1primitive getconvertedvalue(asn1objectidentifier oid, string value);
}
