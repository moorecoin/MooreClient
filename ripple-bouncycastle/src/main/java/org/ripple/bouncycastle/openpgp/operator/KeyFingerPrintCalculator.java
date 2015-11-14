package org.ripple.bouncycastle.openpgp.operator;

import org.ripple.bouncycastle.bcpg.publickeypacket;
import org.ripple.bouncycastle.openpgp.pgpexception;

public interface keyfingerprintcalculator
{
    byte[] calculatefingerprint(publickeypacket publicpk)
        throws pgpexception;
}
