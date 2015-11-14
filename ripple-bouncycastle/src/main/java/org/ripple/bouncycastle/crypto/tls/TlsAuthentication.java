package org.ripple.bouncycastle.crypto.tls;

import java.io.ioexception;

public interface tlsauthentication
{
    /**
     * called by the protocol handler to report the server certificate
     * note: this method is responsible for certificate verification and validation
     *
     * @param servercertificate the server certificate received
     * @throws ioexception
     */
    void notifyservercertificate(certificate servercertificate)
        throws ioexception;

    /**
     * return client credentials in response to server's certificate request
     *
     * @param certificaterequest details of the certificate request
     * @return a tlscredentials object or null for no client authentication
     * @throws ioexception
     */
    tlscredentials getclientcredentials(certificaterequest certificaterequest)
        throws ioexception;
}
