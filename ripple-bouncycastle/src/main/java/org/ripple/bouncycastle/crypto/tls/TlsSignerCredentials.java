package org.ripple.bouncycastle.crypto.tls;

import java.io.ioexception;

public interface tlssignercredentials
    extends tlscredentials
{
    byte[] generatecertificatesignature(byte[] md5andsha1)
        throws ioexception;
}
