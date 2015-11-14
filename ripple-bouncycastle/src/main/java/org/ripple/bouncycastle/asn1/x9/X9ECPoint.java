package org.ripple.bouncycastle.asn1.x9;

import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.deroctetstring;
import org.ripple.bouncycastle.math.ec.eccurve;
import org.ripple.bouncycastle.math.ec.ecpoint;

/**
 * class for describing an ecpoint as a der object.
 */
public class x9ecpoint
    extends asn1object
{
    ecpoint p;

    public x9ecpoint(
        ecpoint p)
    {
        this.p = p;
    }

    public x9ecpoint(
        eccurve          c,
        asn1octetstring  s)
    {
        this.p = c.decodepoint(s.getoctets());
    }

    public ecpoint getpoint()
    {
        return p;
    }

    /**
     * produce an object suitable for an asn1outputstream.
     * <pre>
     *  ecpoint ::= octet string
     * </pre>
     * <p>
     * octet string produced using ecpoint.getencoded().
     */
    public asn1primitive toasn1primitive()
    {
        return new deroctetstring(p.getencoded());
    }
}
