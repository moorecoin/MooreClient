package org.ripple.bouncycastle.openpgp.operator;

import org.ripple.bouncycastle.bcpg.containedpacket;
import org.ripple.bouncycastle.openpgp.pgpexception;

public abstract class pgpkeyencryptionmethodgenerator
{
    public abstract containedpacket generate(int encalgorithm, byte[] sessioninfo)
        throws pgpexception;
}
