package org.ripple.bouncycastle.asn1.smime;

import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.derset;
import org.ripple.bouncycastle.asn1.cms.attribute;

public class smimecapabilitiesattribute
    extends attribute
{
    public smimecapabilitiesattribute(
        smimecapabilityvector capabilities)
    {
        super(smimeattributes.smimecapabilities,
                new derset(new dersequence(capabilities.toasn1encodablevector())));
    }
}
