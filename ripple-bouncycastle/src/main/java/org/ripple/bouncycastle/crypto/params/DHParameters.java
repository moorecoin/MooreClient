package org.ripple.bouncycastle.crypto.params;

import java.math.biginteger;

import org.ripple.bouncycastle.crypto.cipherparameters;

public class dhparameters
    implements cipherparameters
{
    private static final int default_minimum_length = 160;

    // not final due to compiler bug in "simpler" jdks
    private biginteger              g;
    private biginteger              p;
    private biginteger              q;
    private biginteger              j;
    private int                     m;
    private int                     l;
    private dhvalidationparameters  validation;

    private static int getdefaultmparam(
        int lparam)
    {
        if (lparam == 0)
        {
            return default_minimum_length;
        }

        return lparam < default_minimum_length ? lparam : default_minimum_length;
    }

    public dhparameters(
        biginteger  p,
        biginteger  g)
    {
        this(p, g, null, 0);
    }

    public dhparameters(
        biginteger  p,
        biginteger  g,
        biginteger  q)
    {
        this(p, g, q, 0);
    }

    public dhparameters(
        biginteger  p,
        biginteger  g,
        biginteger  q,
        int         l)
    {
        this(p, g, q, getdefaultmparam(l), l, null, null);
    }

    public dhparameters(
        biginteger  p,
        biginteger  g,
        biginteger  q,
        int         m,
        int         l)
    {
        this(p, g, q, m, l, null, null);
    }

    public dhparameters(
        biginteger              p,
        biginteger              g,
        biginteger              q,
        biginteger              j,
        dhvalidationparameters  validation)
    {
        this(p, g, q, default_minimum_length, 0, j, validation);
    }

    public dhparameters(
        biginteger              p,
        biginteger              g,
        biginteger              q,
        int                     m,
        int                     l,
        biginteger              j,
        dhvalidationparameters  validation)
    {
        if (l != 0)
        {
            biginteger bigl = biginteger.valueof(2l ^ (l - 1));
            if (bigl.compareto(p) == 1)
            {
                throw new illegalargumentexception("when l value specified, it must satisfy 2^(l-1) <= p");
            }
            if (l < m)
            {
                throw new illegalargumentexception("when l value specified, it may not be less than m value");
            }
        }

        this.g = g;
        this.p = p;
        this.q = q;
        this.m = m;
        this.l = l;
        this.j = j;
        this.validation = validation;
    }

    public biginteger getp()
    {
        return p;
    }

    public biginteger getg()
    {
        return g;
    }

    public biginteger getq()
    {
        return q;
    }

    /**
     * return the subgroup factor j.
     *
     * @return subgroup factor
     */
    public biginteger getj()
    {
        return j;
    }

    /**
     * return the minimum length of the private value.
     *
     * @return the minimum length of the private value in bits.
     */
    public int getm()
    {
        return m;
    }

    /**
     * return the private value length in bits - if set, zero otherwise
     *
     * @return the private value length in bits, zero otherwise.
     */
    public int getl()
    {
        return l;
    }

    public dhvalidationparameters getvalidationparameters()
    {
        return validation;
    }

    public boolean equals(
        object  obj)
    {
        if (!(obj instanceof dhparameters))
        {
            return false;
        }

        dhparameters    pm = (dhparameters)obj;

        if (this.getq() != null)
        {
            if (!this.getq().equals(pm.getq()))
            {
                return false;
            }
        }
        else
        {
            if (pm.getq() != null)
            {
                return false;
            }
        }

        return pm.getp().equals(p) && pm.getg().equals(g);
    }
    
    public int hashcode()
    {
        return getp().hashcode() ^ getg().hashcode() ^ (getq() != null ? getq().hashcode() : 0);
    }
}
