package org.ripple.bouncycastle.openpgp.operator;

import org.ripple.bouncycastle.openpgp.pgpexception;

public interface pgpdigestcalculatorprovider
{
    pgpdigestcalculator get(int algorithm)
        throws pgpexception;
}
