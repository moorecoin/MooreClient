package org.ripple.bouncycastle.crypto.params;

/**
 * @deprecated use aeadparameters
 */
public class ccmparameters
    extends aeadparameters
{
    /**
     * base constructor.
     * 
     * @param key key to be used by underlying cipher
     * @param macsize macsize in bits
     * @param nonce nonce to be used
     * @param associatedtext associated text, if any
     */
    public ccmparameters(keyparameter key, int macsize, byte[] nonce, byte[] associatedtext)
    {
        super(key, macsize, nonce, associatedtext);
    }
}
