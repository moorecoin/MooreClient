package org.ripple.bouncycastle.crypto.params;

import org.ripple.bouncycastle.crypto.cipherparameters;

import java.security.securerandom;

public class parameterswithrandom
    implements cipherparameters
{
    private securerandom        random;
    private cipherparameters    parameters;

    public parameterswithrandom(
        cipherparameters    parameters,
        securerandom        random)
    {
        this.random = random;
        this.parameters = parameters;
    }

    public parameterswithrandom(
        cipherparameters    parameters)
    {
        this(parameters, new securerandom());
    }

    public securerandom getrandom()
    {
        return random;
    }

    public cipherparameters getparameters()
    {
        return parameters;
    }
}
