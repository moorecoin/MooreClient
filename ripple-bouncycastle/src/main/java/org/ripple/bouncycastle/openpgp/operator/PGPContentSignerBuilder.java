package org.ripple.bouncycastle.openpgp.operator;

import org.ripple.bouncycastle.openpgp.pgpexception;
import org.ripple.bouncycastle.openpgp.pgpprivatekey;

public interface pgpcontentsignerbuilder
{
    public pgpcontentsigner build(final int signaturetype, final pgpprivatekey privatekey)
        throws pgpexception;
}
