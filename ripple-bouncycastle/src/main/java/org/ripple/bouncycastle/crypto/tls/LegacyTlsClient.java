package org.ripple.bouncycastle.crypto.tls;

import java.io.ioexception;

/**
 * a temporary class to use legacytlsauthentication
 *
 * @deprecated
 */
public class legacytlsclient
    extends defaulttlsclient
{
    /**
     * @deprecated
     */
    protected certificateverifyer verifyer;

    /**
     * @deprecated
     */
    public legacytlsclient(certificateverifyer verifyer)
    {
        super();

        this.verifyer = verifyer;
    }

    public tlsauthentication getauthentication()
        throws ioexception
    {
        return new legacytlsauthentication(verifyer);
    }
}
