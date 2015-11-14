package org.ripple.bouncycastle.crypto.tls;

import java.io.ioexception;

/**
 * a temporary class to wrap old certificateverifyer stuff for new tlsauthentication
 *
 * @deprecated
 */
public class legacytlsauthentication
    extends serveronlytlsauthentication
{
    protected certificateverifyer verifyer;

    public legacytlsauthentication(certificateverifyer verifyer)
    {
        this.verifyer = verifyer;
    }

    public void notifyservercertificate(certificate servercertificate)
        throws ioexception
    {
        if (!this.verifyer.isvalid(servercertificate.getcertificatelist()))
        {
            throw new tlsfatalalert(alertdescription.user_canceled);
        }
    }
}
