package org.ripple.bouncycastle.jce.spec;

import java.security.spec.algorithmparameterspec;

/**
 * parameter spec for an integrated encryptor, as in ieee p1363a
 */
public class iesparameterspec
    implements algorithmparameterspec
{
    private byte[] derivation;
    private byte[] encoding;
    private int mackeysize;
    private int cipherkeysize;


    /**
     * set the ies engine parameters.
     *
     * @param derivation the optional derivation vector for the kdf.
     * @param encoding   the optional encoding vector for the kdf.
     * @param mackeysize the key size (in bits) for the mac.
     */
    public iesparameterspec(
        byte[] derivation,
        byte[] encoding,
        int mackeysize)
    {
        this(derivation, encoding, mackeysize, -1);
    }


    /**
     * set the ies engine parameters.
     *
     * @param derivation    the optional derivation vector for the kdf.
     * @param encoding      the optional encoding vector for the kdf.
     * @param mackeysize    the key size (in bits) for the mac.
     * @param cipherkeysize the key size (in bits) for the block cipher.
     */
    public iesparameterspec(
        byte[] derivation,
        byte[] encoding,
        int mackeysize,
        int cipherkeysize)
    {
        if (derivation != null)
        {
            this.derivation = new byte[derivation.length];
            system.arraycopy(derivation, 0, this.derivation, 0, derivation.length);
        }
        else
        {
            this.derivation = null;
        }

        if (encoding != null)
        {
            this.encoding = new byte[encoding.length];
            system.arraycopy(encoding, 0, this.encoding, 0, encoding.length);
        }
        else
        {
            this.encoding = null;
        }

        this.mackeysize = mackeysize;
        this.cipherkeysize = cipherkeysize;
    }


    /**
     * return the derivation vector.
     */
    public byte[] getderivationv()
    {
        return derivation;
    }

    /**
     * return the encoding vector.
     */
    public byte[] getencodingv()
    {
        return encoding;
    }

    /**
     * return the key size in bits for the mac used with the message
     */
    public int getmackeysize()
    {
        return mackeysize;
    }

    /**
     * return the key size in bits for the block cipher used with the message
     */
    public int getcipherkeysize()
    {
        return cipherkeysize;
    }

}
