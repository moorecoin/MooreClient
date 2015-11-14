package org.ripple.bouncycastle.crypto.tls;

import java.io.ioexception;

public interface tlscipher
{
    int getplaintextlimit(int ciphertextlimit);

    byte[] encodeplaintext(long seqno, short type, byte[] plaintext, int offset, int len)
        throws ioexception;

    byte[] decodeciphertext(long seqno, short type, byte[] ciphertext, int offset, int len)
        throws ioexception;
}
