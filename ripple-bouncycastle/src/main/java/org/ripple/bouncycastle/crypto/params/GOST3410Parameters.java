package org.ripple.bouncycastle.crypto.params;

import org.ripple.bouncycastle.crypto.cipherparameters;

import java.math.biginteger;

public class gost3410parameters
   implements cipherparameters
{
    private biginteger              p;
    private biginteger              q;
    private biginteger              a;
    private gost3410validationparameters validation;

    public gost3410parameters(
        biginteger  p,
        biginteger  q,
        biginteger  a)
    {
        this.p = p;
        this.q = q;
        this.a = a;
    }

    public gost3410parameters(
        biginteger              p,
        biginteger              q,
        biginteger              a,
        gost3410validationparameters params)
    {
        this.a = a;
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

    public biginteger geta()
    {
        return a;
    }

    public gost3410validationparameters getvalidationparameters()
    {
        return validation;
    }

    public int hashcode()
    {
        return p.hashcode() ^ q.hashcode() ^ a.hashcode();
    }

    public boolean equals(
        object  obj)
    {
        if (!(obj instanceof gost3410parameters))
        {
            return false;
        }

        gost3410parameters    pm = (gost3410parameters)obj;

        return (pm.getp().equals(p) && pm.getq().equals(q) && pm.geta().equals(a));
    }
}
