package org.ripple.bouncycastle.crypto;

/**
 * this exception is thrown if a buffer that is meant to have output
 * copied into it turns out to be too short, or if we've been given 
 * insufficient input. in general this exception will get thrown rather
 * than an arrayoutofbounds exception.
 */
public class datalengthexception 
    extends runtimecryptoexception
{
    /**
     * base constructor.
     */
    public datalengthexception()
    {
    }

    /**
     * create a datalengthexception with the given message.
     *
     * @param message the message to be carried with the exception.
     */
    public datalengthexception(
        string  message)
    {
        super(message);
    }
}
