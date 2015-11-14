package org.ripple.bouncycastle.crypto;

/**
 * this exception is thrown whenever we find something we don't expect in a
 * message.
 */
public class invalidciphertextexception 
    extends cryptoexception
{
    /**
     * base constructor.
     */
    public invalidciphertextexception()
    {
    }

    /**
     * create a invalidciphertextexception with the given message.
     *
     * @param message the message to be carried with the exception.
     */
    public invalidciphertextexception(
        string  message)
    {
        super(message);
    }

    /**
     * create a invalidciphertextexception with the given message.
     *
     * @param message the message to be carried with the exception.
     * @param cause the root cause of the exception.
     */
    public invalidciphertextexception(
        string  message,
        throwable cause)
    {
        super(message, cause);
    }
}
