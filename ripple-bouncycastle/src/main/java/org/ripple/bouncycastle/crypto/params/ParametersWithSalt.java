package org.ripple.bouncycastle.crypto.params;

import org.ripple.bouncycastle.crypto.cipherparameters;

/**
 * cipher parameters with a fixed salt value associated with them.
 */
public class parameterswithsalt
    implements cipherparameters
{
    private byte[]              salt;
    private cipherparameters    parameters;

    public parameterswithsalt(
        cipherparameters    parameters,
        byte[]              salt)
    {
        this(parameters, salt, 0, salt.length);
    }

    public parameterswithsalt(
        cipherparameters    parameters,
        byte[]              salt,
        int                 saltoff,
        int                 saltlen)
    {
        this.salt = new byte[saltlen];
        this.parameters = parameters;

        system.arraycopy(salt, saltoff, this.salt, 0, saltlen);
    }

    public byte[] getsalt()
    {
        return salt;
    }

    public cipherparameters getparameters()
    {
        return parameters;
    }
}
