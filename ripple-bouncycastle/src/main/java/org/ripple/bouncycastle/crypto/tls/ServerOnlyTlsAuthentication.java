package org.ripple.bouncycastle.crypto.tls;

public abstract class serveronlytlsauthentication
    implements tlsauthentication
{
    public final tlscredentials getclientcredentials(certificaterequest certificaterequest)
    {
        return null;
    }
}
