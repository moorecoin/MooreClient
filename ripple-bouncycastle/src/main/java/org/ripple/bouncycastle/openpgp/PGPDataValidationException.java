package org.ripple.bouncycastle.openpgp;

/**
 * thrown if the iv at the start of a data stream indicates the wrong key
 * is being used.
 */
public class pgpdatavalidationexception 
    extends pgpexception
{
    /**
     * @param message
     */
    public pgpdatavalidationexception(string message)
    {
        super(message);
    }
}
