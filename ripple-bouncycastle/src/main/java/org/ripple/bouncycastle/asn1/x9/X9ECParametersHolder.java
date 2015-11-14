package org.ripple.bouncycastle.asn1.x9;

public abstract class x9ecparametersholder
{
    private x9ecparameters params;

    public x9ecparameters getparameters()
    {
        if (params == null)
        {
            params = createparameters();
        }

        return params;
    }

    protected abstract x9ecparameters createparameters();
}
