package org.ripple.bouncycastle.openpgp.operator;

import org.ripple.bouncycastle.openpgp.pgpexception;

public interface pgpdatadecryptorfactory
{
    public pgpdatadecryptor createdatadecryptor(boolean withintegritypacket, int encalgorithm, byte[] key)
        throws pgpexception;
}
