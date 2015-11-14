package org.ripple.bouncycastle.crypto.tls;

/**
 * this should be implemented by any class which can find out, if a given certificate
 * chain is being accepted by an client.
 *
 * @deprecated perform certificate verification in tlsauthentication implementation
 */
public interface certificateverifyer
{
    /**
     * @param certs the certs, which are part of the chain.
     * @return true, if the chain is accepted, false otherwise.
     */
    public boolean isvalid(org.ripple.bouncycastle.asn1.x509.certificate[] certs);
}
