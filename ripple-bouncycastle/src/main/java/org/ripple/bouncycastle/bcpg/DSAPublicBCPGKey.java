package org.ripple.bouncycastle.bcpg;

import java.io.*;
import java.math.biginteger;

/**
 * base class for a dsa public key.
 */
public class dsapublicbcpgkey 
    extends bcpgobject implements bcpgkey 
{
    mpinteger    p;
    mpinteger    q;
    mpinteger    g;
    mpinteger    y;
    
    /**
     * @param in the stream to read the packet from.
     */
    public dsapublicbcpgkey(
        bcpginputstream    in)
        throws ioexception
    {
        this.p = new mpinteger(in);
        this.q = new mpinteger(in);
        this.g = new mpinteger(in);
        this.y = new mpinteger(in);
    }

    public dsapublicbcpgkey(
        biginteger    p,
        biginteger    q,
        biginteger    g,
        biginteger    y)
    {
        this.p = new mpinteger(p);
        this.q = new mpinteger(q);
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
    
    public void encode(
        bcpgoutputstream    out)
        throws ioexception
    {
        out.writeobject(p);
        out.writeobject(q);
        out.writeobject(g);
        out.writeobject(y);
    }
    
    /**
     * @return g
     */
    public biginteger getg()
    {
        return g.getvalue();
    }

    /**
     * @return p
     */
    public biginteger getp()
    {
        return p.getvalue();
    }

    /**
     * @return q
     */
    public biginteger getq()
    {
        return q.getvalue();
    }

    /**
     * @return g
     */
    public biginteger gety()
    {
        return y.getvalue();
    }

}
