package org.ripple.bouncycastle.crypto.params;

import java.math.biginteger;

import org.ripple.bouncycastle.crypto.cipherparameters;

public class dsaparameters
    implements cipherparameters
{
    private biginteger              g;
    private biginteger              q;
    private biginteger              p;
    private dsavalidationparameters validation;

    public dsaparameters(
        biginteger  p,
        biginteger  q,
        biginteger  g)
    {
        this.g = g;
        this.p = p;
        this.q = q;
    }   

    public dsaparameters(
        biginteger              p,
        biginteger              q,
        biginteger              g,
        dsavalidationparameters params)
    {
        this.g = g;
        this.p = p;
        this.q = q;
        this.validation = params;
    }   

    public biginteger getp()
    {
        return p;
    }

    public biginteger getq()
    {
        return q;
    }

    public biginteger getg()
    {
        return g;
    }

    public dsavalidationparameters getvalidationparameters()
    {
        return validation;
    }

    public boolean equals(
        object  obj)
    {
        if (!(obj instanceof dsaparameters))
        {
            return false;
        }

        dsaparameters    pm = (dsaparameters)obj;

        return (pm.getp().equals(p) && pm.getq().equals(q) && pm.getg().equals(g));
    }
    
    public int hashcode()
    {
        return getp().hashcode() ^ getq().hashcode() ^ getg().hashcode();
    }
}
