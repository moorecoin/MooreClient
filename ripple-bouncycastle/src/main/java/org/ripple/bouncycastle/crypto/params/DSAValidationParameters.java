package org.ripple.bouncycastle.crypto.params;

import org.ripple.bouncycastle.util.arrays;

public class dsavalidationparameters
{
    private int usageindex;
    private byte[]  seed;
    private int     counter;

    public dsavalidationparameters(
        byte[]  seed,
        int     counter)
    {
        this(seed, counter, -1);
    }

    public dsavalidationparameters(
        byte[]  seed,
        int     counter,
        int     usageindex)
    {
        this.seed = seed;
        this.counter = counter;
        this.usageindex = usageindex;
    }

    public int getcounter()
    {
        return counter;
    }

    public byte[] getseed()
    {
        return seed;
    }

    public int getusageindex()
    {
        return usageindex;
    }

    public int hashcode()
    {
        return counter ^ arrays.hashcode(seed);
    }
    
    public boolean equals(
        object o)
    {
        if (!(o instanceof dsavalidationparameters))
        {
            return false;
        }

        dsavalidationparameters  other = (dsavalidationparameters)o;

        if (other.counter != this.counter)
        {
            return false;
        }

        return arrays.areequal(this.seed, other.seed);
    }
}
