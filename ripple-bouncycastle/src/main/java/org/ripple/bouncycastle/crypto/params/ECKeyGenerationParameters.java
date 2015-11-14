package org.ripple.bouncycastle.crypto.params;

import java.security.securerandom;

import org.ripple.bouncycastle.crypto.keygenerationparameters;

public class eckeygenerationparameters
    extends keygenerationparameters
{
    private ecdomainparameters  domainparams;

    public eckeygenerationparameters(
        ecdomainparameters      domainparams,
        securerandom            random)
    {
        super(random, domainparams.getn().bitlength());

        this.domainparams = domainparams;
    }

    public ecdomainparameters getdomainparameters()
    {
        return domainparams;
    }
}
