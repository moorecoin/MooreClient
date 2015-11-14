package org.ripple.bouncycastle.crypto.params;

import org.ripple.bouncycastle.crypto.cipherparameters;

/**
 * parameters for using an integrated cipher in stream mode.
 */
public class iesparameters
    implements cipherparameters
{
    private byte[]  derivation;
    private byte[]  encoding;
    private int     mackeysize;

    /**
     * @param derivation the derivation parameter for the kdf function.
     * @param encoding the encoding parameter for the kdf function.
     * @param mackeysize the size of the mac key (in bits).
     */
    public iesparameters(
        byte[]  derivation,
        byte[]  encoding,
        int     mackeysize)
    {
        this.derivation = derivation;
        this.encoding = encoding;
        this.mackeysize = mackeysize;
    }

    public byte[] getderivationv()
    {
        return derivation;
    }

    public byte[] getencodingv()
    {
        return encoding;
    }

    public int getmackeysize()
    {
        return mackeysize;
    }
}
