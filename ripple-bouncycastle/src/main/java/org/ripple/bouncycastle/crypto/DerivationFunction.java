package org.ripple.bouncycastle.crypto;

/**
 * base interface for general purpose byte derivation functions.
 */
public interface derivationfunction
{
    public void init(derivationparameters param);

    /**
     * return the message digest used as the basis for the function
     */
    public digest getdigest();

    public int generatebytes(byte[] out, int outoff, int len)
        throws datalengthexception, illegalargumentexception;
}
