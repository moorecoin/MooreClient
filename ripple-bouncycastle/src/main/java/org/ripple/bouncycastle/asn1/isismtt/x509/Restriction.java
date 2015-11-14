package org.ripple.bouncycastle.asn1.isismtt.x509;

import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.x500.directorystring;

/**
 * some other restriction regarding the usage of this certificate.
 * <p/>
 * <pre>
 *  restrictionsyntax ::= directorystring (size(1..1024))
 * </pre>
 */
public class restriction
    extends asn1object
{
    private directorystring restriction;

    public static restriction getinstance(object obj)
    {
        if (obj instanceof restriction)
        {
            return (restriction)obj;
        }

        if (obj != null)
        {
            return new restriction(directorystring.getinstance(obj));
        }

        return null;
    }

    /**
     * constructor from directorystring.
     * <p/>
     * the directorystring is of type restrictionsyntax:
     * <p/>
     * <pre>
     *      restrictionsyntax ::= directorystring (size(1..1024))
     * </pre>
     *
     * @param restriction a directorystring.
     */
    private restriction(directorystring restriction)
    {
        this.restriction = restriction;
    }

    /**
     * constructor from a given details.
     *
     * @param restriction the describtion of the restriction.
     */
    public restriction(string restriction)
    {
        this.restriction = new directorystring(restriction);
    }

    public directorystring getrestriction()
    {
        return restriction;
    }

    /**
     * produce an object suitable for an asn1outputstream.
     * <p/>
     * returns:
     * <p/>
     * <pre>
     *      restrictionsyntax ::= directorystring (size(1..1024))
     * <p/>
     * </pre>
     *
     * @return a derobject
     */
    public asn1primitive toasn1primitive()
    {
        return restriction.toasn1primitive();
    }
}
