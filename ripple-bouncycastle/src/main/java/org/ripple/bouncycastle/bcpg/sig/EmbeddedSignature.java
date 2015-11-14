package org.ripple.bouncycastle.bcpg.sig;

import org.ripple.bouncycastle.bcpg.signaturesubpacket;
import org.ripple.bouncycastle.bcpg.signaturesubpackettags;

/**
 * packet embedded signature
 */
public class embeddedsignature
    extends signaturesubpacket
{
    public embeddedsignature(
        boolean    critical,
        byte[]     data)
    {
        super(signaturesubpackettags.embedded_signature, critical, data);
    }
}