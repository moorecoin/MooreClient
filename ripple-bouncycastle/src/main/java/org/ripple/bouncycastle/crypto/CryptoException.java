package org.ripple.bouncycastle.crypto;

/**
 * the foundation class for the hard exceptions thrown by the crypto packages.
 */
public class cryptoexception 
    extends exception
{
    private throwable cause;

    /**
     * base constructor.
     */
    public cryptoexception()
    {
    }

    /**
     * create a cryptoexception with the given message.
     *
     * @param message the message to be carried with the exception.
     */
    public cryptoexception(
        string  message)
    {
        super(message);
    }

    /**
     * create a cryptoexception with the given message and underlying cause.
     *
     * @param message message describing exception.
     * @param cause the throwable that was the underlying cause.
     */
    public cryptoexception(
        string  message,
        throwable cause)
    {
        super(message);

        this.cause = cause;
    }

    public throwable getcause()
    {
        return cause;
    }
}
