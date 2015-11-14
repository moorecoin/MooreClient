package org.ripple.bouncycastle.bcpg;

import java.io.*;
import java.math.biginteger;

/**
 * base class for an rsa secret (or private) key.
 */
public class rsasecretbcpgkey 
    extends bcpgobject implements bcpgkey 
{
    mpinteger    d;
    mpinteger    p;
    mpinteger    q;
    mpinteger    u;
    
    biginteger    expp, expq, crt;
    
    /**
     * 
     * @param in
     * @throws ioexception
     */
    public rsasecretbcpgkey(
        bcpginputstream    in)
        throws ioexception
    {
        this.d = new mpinteger(in);
        this.p = new mpinteger(in);
        this.q = new mpinteger(in);
        this.u = new mpinteger(in);

        expp = d.getvalue().remainder(p.getvalue().subtract(biginteger.valueof(1)));
        expq = d.getvalue().remainder(q.getvalue().subtract(biginteger.valueof(1)));
        crt = q.getvalue().modinverse(p.getvalue());
    }
    
    /**
     * 
     * @param d
     * @param p
     * @param q
     */
    public rsasecretbcpgkey(
        biginteger    d,
        biginteger    p,
        biginteger    q)
    {
        //
        // pgp requires (p < q)
        //
        int cmp = p.compareto(q);
        if (cmp >= 0)
        {
            if (cmp == 0)
            {
                throw new illegalargumentexception("p and q cannot be equal");
            }

            biginteger tmp = p;
            p = q;
            q = tmp;
        }

        this.d = new mpinteger(d);
        this.p = new mpinteger(p);
        this.q = new mpinteger(q);
        this.u = new mpinteger(p.modinverse(q));

        expp = d.remainder(p.subtract(biginteger.valueof(1)));
        expq = d.remainder(q.subtract(biginteger.valueof(1)));
        crt = q.modinverse(p);
    }
    
    /**
     * return the modulus for this key.
     * 
     * @return biginteger
     */
    public biginteger getmodulus()
    {
        return p.getvalue().multiply(q.getvalue());
    }
    
    /**
     * return the private exponent for this key.
     * 
     * @return biginteger
     */
    public biginteger getprivateexponent()
    {
        return d.getvalue();
    }
    
    /**
     * return the prime p
     */
    public biginteger getprimep()
    {
        return p.getvalue();
    }
    
    /**
     * return the prime q
     */
    public biginteger getprimeq()
    {
        return q.getvalue();
    }
    
    /**
     * return the prime exponent of p
     */
    public biginteger getprimeexponentp()
    {
        return expp;
    }
    
    /**
     * return the prime exponent of q
     */
    public biginteger getprimeexponentq()
    {
        return expq;
    }
    
    /**
     * return the crt coefficient
     */
    public biginteger getcrtcoefficient()
    {
        return crt;
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
        out.writeobject(d);
        out.writeobject(p);
        out.writeobject(q);
        out.writeobject(u);
    }
}
