package org.ripple.bouncycastle.openpgp.operator;

import java.math.biginteger;

import org.ripple.bouncycastle.openpgp.pgpexception;

public interface publickeydatadecryptorfactory
    extends pgpdatadecryptorfactory
{
    public byte[] recoversessiondata(int keyalgorithm, biginteger[] seckeydata)
            throws pgpexception;
}
