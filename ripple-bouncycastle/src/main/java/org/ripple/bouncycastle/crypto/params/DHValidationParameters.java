package org.ripple.bouncycastle.crypto.params;

import org.ripple.bouncycastle.util.arrays;

public class dhvalidationparameters
{
    private byte[]  seed;
    private int     counter;

    public dhvalidationparameters(
        byte[]  seed,
        int     counter)
    {
        this.seed = seed;
        this.counter = counter;
    }

    public int getcounter()
    {
        return counter;
    }

    public byte[] getseed()
    {
        return seed;
    }

    public boolean equals(
        object o)
    {
        if (!(o instanceof dhvalidationparameters))
        {
            return false;
        }

        dhvalidationparameters  other = (dhvalidationparameters)o;

        if (other.counter != this.counter)
        {
            return false;
        }

        return arrays.areequal(this.seed, other.seed);
    }

    public int hashcode()
    {
        return counter ^ arrays.hashcode(seed);
    }
}
