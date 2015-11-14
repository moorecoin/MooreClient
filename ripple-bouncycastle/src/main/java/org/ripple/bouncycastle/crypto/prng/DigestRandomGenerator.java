package org.ripple.bouncycastle.crypto.prng;

import org.ripple.bouncycastle.crypto.digest;

/**
 * random generation based on the digest with counter. calling addseedmaterial will
 * always increase the entropy of the hash.
 * <p>
 * internal access to the digest is synchronized so a single one of these can be shared.
 * </p>
 */
public class digestrandomgenerator
    implements randomgenerator
{
    private static long         cycle_count = 10;

    private long                statecounter;
    private long                seedcounter;
    private digest              digest;
    private byte[]              state;
    private byte[]              seed;

    // public constructors
    public digestrandomgenerator(
        digest digest)
    {
        this.digest = digest;

        this.seed = new byte[digest.getdigestsize()];
        this.seedcounter = 1;

        this.state = new byte[digest.getdigestsize()];
        this.statecounter = 1;
    }

    public void addseedmaterial(byte[] inseed)
    {
        synchronized (this)
        {
            digestupdate(inseed);
            digestupdate(seed);
            digestdofinal(seed);
        }
    }

    public void addseedmaterial(long rseed)
    {
        synchronized (this)
        {
            digestaddcounter(rseed);
            digestupdate(seed);

            digestdofinal(seed);
        }
    }

    public void nextbytes(byte[] bytes)
    {
        nextbytes(bytes, 0, bytes.length);
    }

    public void nextbytes(byte[] bytes, int start, int len)
    {
        synchronized (this)
        {
            int stateoff = 0;

            generatestate();

            int end = start + len;
            for (int i = start; i != end; i++)
            {
                if (stateoff == state.length)
                {
                    generatestate();
                    stateoff = 0;
                }
                bytes[i] = state[stateoff++];
            }
        }
    }

    private void cycleseed()
    {
        digestupdate(seed);
        digestaddcounter(seedcounter++);

        digestdofinal(seed);
    }

    private void generatestate()
    {
        digestaddcounter(statecounter++);
        digestupdate(state);
        digestupdate(seed);

        digestdofinal(state);

        if ((statecounter % cycle_count) == 0)
        {
            cycleseed();
        }
    }

    private void digestaddcounter(long seed)
    {
        for (int i = 0; i != 8; i++)
        {
            digest.update((byte)seed);
            seed >>>= 8;
        }
    }

    private void digestupdate(byte[] inseed)
    {
        digest.update(inseed, 0, inseed.length);
    }

    private void digestdofinal(byte[] result)
    {
        digest.dofinal(result, 0);
    }
}
