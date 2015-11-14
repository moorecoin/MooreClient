package org.ripple.bouncycastle.crypto.tls;

public abstract class abstracttlspeer
    implements tlspeer
{

    public void notifyalertraised(short alertlevel, short alertdescription, string message, exception cause)
    {
    }

    public void notifyalertreceived(short alertlevel, short alertdescription)
    {
    }
}
