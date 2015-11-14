package org.ripple.bouncycastle.crypto;

/**
 * the foundation class for the exceptions thrown by the crypto packages.
 */
public class runtimecryptoexception 
    extends runtimeexception
{
    /**
     * base constructor.
     */
    public runtimecryptoexception()
    {
    }

    /**
     * create a runtimecryptoexception with the given message.
     *
     * @param message the message to be carried with the exception.
     */
    public runtimecryptoexception(
        string  message)
    {
        super(message);
    }
}
