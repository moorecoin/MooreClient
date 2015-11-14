package org.ripple.bouncycastle.openpgp;

/**
 * generic exception class for pgp encoding/decoding problems
 */
public class pgpexception 
    extends exception 
{
    exception    underlying;
    
    public pgpexception(
        string    message)
    {
        super(message);
    }
    
    public pgpexception(
        string        message,
        exception    underlying)
    {
        super(message);
        this.underlying = underlying;
    }
    
    public exception getunderlyingexception()
    {
        return underlying;
    }
    
    
    public throwable getcause()
    {
        return underlying;
    }
}
