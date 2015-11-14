package org.ripple.bouncycastle.crypto.params;

public class gost3410validationparameters
{
    private int x0;
    private int c;
    private long x0l;
    private long cl;


    public gost3410validationparameters(
        int  x0,
        int  c)
    {
        this.x0 = x0;
        this.c = c;
    }

    public gost3410validationparameters(
        long  x0l,
        long  cl)
    {
        this.x0l = x0l;
        this.cl = cl;
    }

    public int getc()
    {
        return c;
    }

    public int getx0()
    {
        return x0;
    }

    public long getcl()
    {
        return cl;
    }

    public long getx0l()
    {
        return x0l;
    }

    public boolean equals(
        object o)
    {
        if (!(o instanceof gost3410validationparameters))
        {
            return false;
        }

        gost3410validationparameters  other = (gost3410validationparameters)o;

        if (other.c != this.c)
        {
            return false;
        }

        if (other.x0 != this.x0)
        {
            return false;
        }

        if (other.cl != this.cl)
        {
            return false;
        }

        if (other.x0l != this.x0l)
        {
            return false;
        }

        return true;
    }

    public int hashcode()
    {
        return x0 ^ c ^ (int) x0l ^ (int)(x0l >> 32) ^ (int) cl ^ (int)(cl >> 32);
    }
}
