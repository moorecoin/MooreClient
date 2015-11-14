package org.ripple.bouncycastle.crypto.params;

import org.ripple.bouncycastle.crypto.cipherparameters;

public class aeadparameters
    implements cipherparameters
{
    private byte[] associatedtext;
    private byte[] nonce;
    private keyparameter key;
    private int macsize;

    /**
     * base constructor.
     *
     * @param key key to be used by underlying cipher
     * @param macsize macsize in bits
     * @param nonce nonce to be used
     */
   public aeadparameters(keyparameter key, int macsize, byte[] nonce)
    {
       this(key, macsize, nonce, null);
    }

    /**
     * base constructor.
     *
     * @param key key to be used by underlying cipher
     * @param macsize macsize in bits
     * @param nonce nonce to be used
     * @param associatedtext initial associated text, if any
     */
    public aeadparameters(keyparameter key, int macsize, byte[] nonce, byte[] associatedtext)
    {
        this.key = key;
        this.nonce = nonce;
        this.macsize = macsize;
        this.associatedtext = associatedtext;
    }

    public keyparameter getkey()
    {
        return key;
    }

    public int getmacsize()
    {
        return macsize;
    }

    public byte[] getassociatedtext()
    {
        return associatedtext;
    }

    public byte[] getnonce()
    {
        return nonce;
    }
}
