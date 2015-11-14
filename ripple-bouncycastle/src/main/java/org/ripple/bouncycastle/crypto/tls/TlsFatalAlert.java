package org.ripple.bouncycastle.crypto.tls;

import java.io.ioexception;

public class tlsfatalalert
    extends ioexception
{
    private static final long serialversionuid = 3584313123679111168l;

    private short alertdescription;

    public tlsfatalalert(short alertdescription)
    {
        this.alertdescription = alertdescription;
    }

    public short getalertdescription()
    {
        return alertdescription;
    }
}
