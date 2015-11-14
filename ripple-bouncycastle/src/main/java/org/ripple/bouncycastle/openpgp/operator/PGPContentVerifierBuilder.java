package org.ripple.bouncycastle.openpgp.operator;

import org.ripple.bouncycastle.openpgp.pgpexception;
import org.ripple.bouncycastle.openpgp.pgppublickey;

public interface pgpcontentverifierbuilder
{
    public pgpcontentverifier build(final pgppublickey publickey)
        throws pgpexception;
}
