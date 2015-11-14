package org.ripple.bouncycastle.bcpg;

import java.math.biginteger;
import java.io.*;

/**
 * base class for an rsa public key.
 */
public class rsapublicbcpgkey 
    extends bcpgobject implements bcpgkey 
{
    mpinteger    n;
    mpinteger    e;
    
    /**
     * construct an rsa public key from the passed in stream.
     * 
     * @param in
     * @throws ioexception
     */
    public rsapublicbcpgkey(
        bcpginputstream    in)
        throws ioexception
    {
        this.n = new mpinteger(in);
        this.e = new mpinteger(in);
    }

    /**
     * 
     * @param n the modulus
     * @param e the public exponent
     */
    public rsapublicbcpgkey(
        biginteger    n,
        biginteger    e)
    {
        this.n = new mpinteger(n);
        this.e = new mpinteger(e);
    }
    
    public biginteger getpublicexponent()
    {
        return e.getvalue();
    }
    
    public biginteger getmodulus()
    {
        return n.getvalue();
    }
    
    /**
     *  return "pgp"
     * 
     * @see org.ripple.bouncycastle.bcpg.bcpgkey#getformat()
     */
    public string getformat() 
    {
        return "pgp";
    }

    /**
     * return the standard pgp encoding of the key.
     * 
     * @see org.ripple.bouncycastle.bcpg.bcpgkey#getencoded()
     */
    public byte[] getencoded() 
    {
        try
        { 
            bytearrayoutputstream    bout = new bytearrayoutputstream();
            bcpgoutputstream         pgpout = new bcpgoutputstream(bout);
        
            pgpout.writeobject(this);
        
            return bout.tobytearray();
        }
        catch (ioexception e)
        {
            return null;
        }
    }
    
    public void encode(
        bcpgoutputstream    out)
        throws ioexception
    {
        out.writeobject(n);
        out.writeobject(e);
    }
}
