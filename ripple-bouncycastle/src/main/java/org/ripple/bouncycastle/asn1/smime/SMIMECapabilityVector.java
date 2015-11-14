package org.ripple.bouncycastle.asn1.smime;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.dersequence;

/**
 * handler for creating a vector s/mime capabilities
 */
public class smimecapabilityvector
{
    private asn1encodablevector    capabilities = new asn1encodablevector();

    public void addcapability(
        asn1objectidentifier capability)
    {
        capabilities.add(new dersequence(capability));
    }

    public void addcapability(
        asn1objectidentifier capability,
        int                 value)
    {
        asn1encodablevector  v = new asn1encodablevector();

        v.add(capability);
        v.add(new asn1integer(value));

        capabilities.add(new dersequence(v));
    }

    public void addcapability(
        asn1objectidentifier capability,
        asn1encodable params)
    {
        asn1encodablevector  v = new asn1encodablevector();

        v.add(capability);
        v.add(params);

        capabilities.add(new dersequence(v));
    }

    public asn1encodablevector toasn1encodablevector()
    {
        return capabilities;
    }
}
