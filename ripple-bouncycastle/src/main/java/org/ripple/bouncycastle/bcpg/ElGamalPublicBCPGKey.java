package org.ripple.bouncycastle.bcpg;

import java.io.*;
import java.math.biginteger;

/**
 * base class for an elgamal public key.
 */
public class elgamalpublicbcpgkey 
    extends bcpgobject implements bcpgkey 
{
    mpinteger    p;
    mpinteger    g;
    mpinteger    y;
    
    /**
     * 
     */
    public elgamalpublicbcpgkey(
        bcpginputstream    in)
        throws ioexception
    {
        this.p = new mpinteger(in);
        this.g = new mpinteger(in);
        this.y = new mpinteger(in);
    }

    public elgamalpublicbcpgkey(
        biginteger    p,
        biginteger    g,
        biginteger    y)
    {
        this.p = new mpinteger(p);
        this.g = new mpinteger(g);
        this.y = new mpinteger(y);
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
    
    public biginteger getp()
    {
        return p.getvalue();
    }
    
    public biginteger getg()
    {
        return g.getvalue();
    }
    
    public biginteger gety()
    {
        return y.getvalue();
    }
    
    public void encode(
        bcpgoutputstream    out)
        throws ioexception
    {
        out.writeobject(p);
        out.writeobject(g);
        out.writeobject(y);
    }
}
