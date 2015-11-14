package org.ripple.bouncycastle.crypto.tls;

import java.io.ioexception;

interface dtlshandshakeretransmit
{
    void receivedhandshakerecord(int epoch, byte[] buf, int off, int len)
        throws ioexception;
}
