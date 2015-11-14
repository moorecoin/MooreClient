package org.ripple.bouncycastle.crypto.params;


public class ieswithcipherparameters
    extends iesparameters
{
    private int cipherkeysize;

    /**
     * @param derivation the derivation parameter for the kdf function.
     * @param encoding the encoding parameter for the kdf function.
     * @param mackeysize the size of the mac key (in bits).
     * @param cipherkeysize the size of the associated cipher key (in bits).
     */
    public ieswithcipherparameters(
        byte[]  derivation,
        byte[]  encoding,
        int     mackeysize,
        int     cipherkeysize)
    {
        super(derivation, encoding, mackeysize);

        this.cipherkeysize = cipherkeysize;
    }

    public int getcipherkeysize()
    {
        return cipherkeysize;
    }
}
