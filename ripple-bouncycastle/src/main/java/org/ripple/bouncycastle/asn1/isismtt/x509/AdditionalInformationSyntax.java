package org.ripple.bouncycastle.asn1.isismtt.x509;

import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.x500.directorystring;

/**
 * some other information of non-restrictive nature regarding the usage of this
 * certificate.
 * 
 * <pre>
 *    additionalinformationsyntax ::= directorystring (size(1..2048))
 * </pre>
 */
public class additionalinformationsyntax
    extends asn1object
{
    private directorystring information;

    public static additionalinformationsyntax getinstance(object obj)
    {
        if (obj instanceof additionalinformationsyntax)
        {
            return (additionalinformationsyntax)obj;
        }

        if (obj != null)
        {
            return new additionalinformationsyntax(directorystring.getinstance(obj));
        }

        return null;
    }

    private additionalinformationsyntax(directorystring information)
    {
        this.information = information;
    }

    /**
     * constructor from a given details.
     *
     * @param information the describtion of the information.
     */
    public additionalinformationsyntax(string information)
    {
        this(new directorystring(information));
    }

    public directorystring getinformation()
    {
        return information;
    }

    /**
     * produce an object suitable for an asn1outputstream.
     * <p/>
     * returns:
     * <p/>
     * <pre>
     *   additionalinformationsyntax ::= directorystring (size(1..2048))
     * </pre>
     *
     * @return a derobject
     */
    public asn1primitive toasn1primitive()
    {
        return information.toasn1primitive();
    }
}
