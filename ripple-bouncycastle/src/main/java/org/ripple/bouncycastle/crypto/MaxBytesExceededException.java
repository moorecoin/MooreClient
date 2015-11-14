package org.ripple.bouncycastle.crypto;

/**
 * this exception is thrown whenever a cipher requires a change of key, iv
 * or similar after x amount of bytes enciphered
 */
public class maxbytesexceededexception
    extends runtimecryptoexception
{
    /**
     * base constructor.
     */
    public maxbytesexceededexception()
    {
    }

    /**
     * create an with the given message.
     *
     * @param message the message to be carried with the exception.
     */
    public maxbytesexceededexception(
        string  message)
    {
        super(message);
    }
}
