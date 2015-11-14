package org.ripple.bouncycastle.openpgp.operator;

import org.ripple.bouncycastle.openpgp.pgpexception;

public interface pgpcontentverifierbuilderprovider
{
    public pgpcontentverifierbuilder get(int keyalgorithm, int hashalgorithm)
        throws pgpexception;
}
