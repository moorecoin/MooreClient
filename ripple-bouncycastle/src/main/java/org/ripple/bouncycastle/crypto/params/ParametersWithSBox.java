package org.ripple.bouncycastle.crypto.params;

import org.ripple.bouncycastle.crypto.cipherparameters;

public class parameterswithsbox
    implements cipherparameters
{
    private cipherparameters  parameters;
    private byte[]            sbox;

    public parameterswithsbox(
        cipherparameters parameters,
        byte[]           sbox)
    {
        this.parameters = parameters;
        this.sbox = sbox;
    }

    public byte[] getsbox()
    {
        return sbox;
    }

    public cipherparameters getparameters()
    {
        return parameters;
    }
}
