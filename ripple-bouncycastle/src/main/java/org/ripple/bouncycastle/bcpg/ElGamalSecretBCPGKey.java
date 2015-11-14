package org.ripple.bouncycastle.bcpg;

import java.io.*;
import java.math.biginteger;

/**
 * base class for an elgamal secret key.
 */
public class elgamalsecretbcpgkey 
    extends bcpgobject implements bcpgkey 
{
    mpinteger    x;
    
    /**
     * 
     * @param in
     * @throws ioexception
     */
    public elgamalsecretbcpgkey(
        bcpginputstream    in)
        throws ioexception
    {
        this.x = new mpinteger(in);
    }
    
    /**
     * 
     * @param x
     */
    public elgamalsecretbcpgkey(
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

    public biginteger getx()
    {
        return x.getvalue();
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
        out.writeobject(x);
    }
}
