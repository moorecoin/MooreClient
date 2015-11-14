package org.ripple.bouncycastle.crypto.params;

import java.math.biginteger;

import org.ripple.bouncycastle.crypto.cipherparameters;

public class elgamalparameters
    implements cipherparameters
{
    private biginteger              g;
    private biginteger              p;
    private int                     l;

    public elgamalparameters(
        biginteger  p,
        biginteger  g)
    {
        this(p, g, 0);
    }

    public elgamalparameters(
        biginteger  p,
        biginteger  g,
        int         l)
    {
        this.g = g;
        this.p = p;
        this.l = l;
    }

    public biginteger getp()
    {
        return p;
    }

    /**
     * return the generator - g
     */
    public biginteger getg()
    {
        return g;
    }

    /**
     * return private value limit - l
     */
    public int getl()
    {
        return l;
    }

    public boolean equals(
        object  obj)
    {
        if (!(obj instanceof elgamalparameters))
        {
            return false;
        }

        elgamalparameters    pm = (elgamalparameters)obj;

        return pm.getp().equals(p) && pm.getg().equals(g) && pm.getl() == l;
    }
    
    public int hashcode()
    {
        return (getp().hashcode() ^ getg().hashcode()) + l;
    }
}
