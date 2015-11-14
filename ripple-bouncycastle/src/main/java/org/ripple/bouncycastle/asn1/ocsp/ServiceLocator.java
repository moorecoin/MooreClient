package org.ripple.bouncycastle.asn1.ocsp;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.x500.x500name;

public class servicelocator
    extends asn1object
{
    x500name    issuer;
    asn1primitive locator;

    /**
     * produce an object suitable for an asn1outputstream.
     * <pre>
     * servicelocator ::= sequence {
     *     issuer    name,
     *     locator   authorityinfoaccesssyntax optional }
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector    v = new asn1encodablevector();

        v.add(issuer);

        if (locator != null)
        {
            v.add(locator);
        }

        return new dersequence(v);
    }
}
