package org.ripple.bouncycastle.pqc.crypto.gmss.util;

import org.ripple.bouncycastle.crypto.digest;

/**
 * this class provides a prng for gmss
 */
public class gmssrandom
{
    /**
     * hash function for the construction of the authentication trees
     */
    private digest messdigesttree;

    /**
     * constructor
     *
     * @param messdigesttree2
     */
    public gmssrandom(digest messdigesttree2)
    {

        this.messdigesttree = messdigesttree2;
    }

    /**
     * computes the next seed value, returns a random byte array and sets
     * outseed to the next value
     *
     * @param outseed byte array in which ((1 + seedin +rand) mod 2^n) will be
     *                stored
     * @return byte array of h(seedin)
     */
    public byte[] nextseed(byte[] outseed)
    {
        // rand <-- h(seedin)
        byte[] rand = new byte[outseed.length];
        messdigesttree.update(outseed, 0, outseed.length);
        rand = new byte[messdigesttree.getdigestsize()];
        messdigesttree.dofinal(rand, 0);

        // seedout <-- (1 + seedin +rand) mod 2^n
        addbytearrays(outseed, rand);
        addone(outseed);

        // system.arraycopy(outseed, 0, outseed, 0, outseed.length);

        return rand;
    }

    private void addbytearrays(byte[] a, byte[] b)
    {

        byte overflow = 0;
        int temp;

        for (int i = 0; i < a.length; i++)
        {
            temp = (0xff & a[i]) + (0xff & b[i]) + overflow;
            a[i] = (byte)temp;
            overflow = (byte)(temp >> 8);
        }
    }

    private void addone(byte[] a)
    {

        byte overflow = 1;
        int temp;

        for (int i = 0; i < a.length; i++)
        {
            temp = (0xff & a[i]) + overflow;
            a[i] = (byte)temp;
            overflow = (byte)(temp >> 8);
        }
    }
}
