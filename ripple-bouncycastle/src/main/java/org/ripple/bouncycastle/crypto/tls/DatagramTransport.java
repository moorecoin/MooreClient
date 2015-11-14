package org.ripple.bouncycastle.crypto.tls;

import java.io.ioexception;

public interface datagramtransport
{

    int getreceivelimit()
        throws ioexception;

    int getsendlimit()
        throws ioexception;

    int receive(byte[] buf, int off, int len, int waitmillis)
        throws ioexception;

    void send(byte[] buf, int off, int len)
        throws ioexception;

    void close()
        throws ioexception;
}
