package org.ripple.bouncycastle.crypto.tls;

public abstract class abstracttlssigner
    implements tlssigner
{

    protected tlscontext context;

    public void init(tlscontext context)
    {
        this.context = context;
    }
}
