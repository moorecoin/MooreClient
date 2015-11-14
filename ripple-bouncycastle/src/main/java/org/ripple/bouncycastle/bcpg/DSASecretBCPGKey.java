package org.ripple.bouncycastle.bcpg;

import java.io.*;
import java.math.biginteger;

/**
 * base class for a dsa secret key.
 */
public class dsasecretbcpgkey 
    extends bcpgobject implements bcpgkey 
{
    mpinteger    x;
    
    /**
     * 
     * @param in
     * @throws ioexception
     */
    public dsasecretbcpgkey(
        bcpginputstream    in)
        throws ioexception
    {
        this.x = new mpinteger(in);
    }

    /**
     * 
     * @param x
     */
    public dsasecretbcpgkey(
        biginteger    x)
    {
        this.x = new mpinteger(x);
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
            bytearrayoutputstream  bout = new bytearrayoutputstream();
            bcpgoutputstream       pgpout = new bcpgoutputstream(bout);
        
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
        out.writeobject(x);
    }
    
    /**
     * @return x
     */
    public biginteger getx()
    {
        return x.getvalue();
    }
}
