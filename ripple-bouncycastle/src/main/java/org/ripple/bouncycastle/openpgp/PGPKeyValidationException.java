package org.ripple.bouncycastle.openpgp;

/**
 * thrown if the key checksum is invalid.
 */
public class pgpkeyvalidationexception 
    extends pgpexception
{
    /**
     * @param message
     */
    public pgpkeyvalidationexception(string message)
    {
        super(message);
    }
}
