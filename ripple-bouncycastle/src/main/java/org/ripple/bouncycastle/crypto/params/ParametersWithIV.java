package org.ripple.bouncycastle.crypto.params;

import org.ripple.bouncycastle.crypto.cipherparameters;

public class parameterswithiv
    implements cipherparameters
{
    private byte[]              iv;
    private cipherparameters    parameters;

    public parameterswithiv(
        cipherparameters    parameters,
        byte[]              iv)
    {
        this(parameters, iv, 0, iv.length);
    }

    public parameterswithiv(
        cipherparameters    parameters,
        byte[]              iv,
        int                 ivoff,
        int                 ivlen)
    {
        this.iv = new byte[ivlen];
        this.parameters = parameters;

        system.arraycopy(iv, ivoff, this.iv, 0, ivlen);
    }

    public byte[] getiv()
    {
        return iv;
    }

    public cipherparameters getparameters()
    {
        return parameters;
    }
}
