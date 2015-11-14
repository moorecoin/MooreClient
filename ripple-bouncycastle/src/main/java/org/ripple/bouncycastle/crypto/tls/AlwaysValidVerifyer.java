package org.ripple.bouncycastle.crypto.tls;

/**
 * a certificate verifyer, that will always return true.
 * <p/>
 * <pre>
 * do not use this file unless you know exactly what you are doing.
 * </pre>
 *
 * @deprecated perform certificate verification in tlsauthentication implementation
 */
public class alwaysvalidverifyer
    implements certificateverifyer
{
    /**
     * return true.
     *
     * @see org.ripple.bouncycastle.crypto.tls.certificateverifyer#isvalid(org.ripple.bouncycastle.asn1.x509.certificate[])
     */
    public boolean isvalid(org.ripple.bouncycastle.asn1.x509.certificate[] certs)
    {
        return true;
    }
}
