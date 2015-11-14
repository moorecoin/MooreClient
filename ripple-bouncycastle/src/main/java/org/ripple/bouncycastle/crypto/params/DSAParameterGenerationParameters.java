package org.ripple.bouncycastle.crypto.params;

import java.security.securerandom;

public class dsaparametergenerationparameters
{
    public static final int digital_signature_usage = 1;
    public static final int key_establishment_usage = 2;

    private final int l;
    private final int n;
    private final int usageindex;
    private final int certainty;
    private final securerandom random;

    /**
     * construct without a usage index, this will do a random construction of g.
     *
     * @param l desired length of prime p in bits (the effective key size).
     * @param n desired length of prime q in bits.
     * @param certainty certainty level for prime number generation.
     * @param random the source of randomness to use.
     */
    public dsaparametergenerationparameters(
        int l,
        int n,
        int certainty,
        securerandom random)
    {
        this(l, n, certainty, random, -1);
    }

    /**
     * construct for a specific usage index - this has the effect of using verifiable canonical generation of g.
     *
     * @param l desired length of prime p in bits (the effective key size).
     * @param n desired length of prime q in bits.
     * @param certainty certainty level for prime number generation.
     * @param random the source of randomness to use.
     * @param usageindex a valid usage index.
     */
    public dsaparametergenerationparameters(
        int l,
        int n,
        int certainty,
        securerandom random,
        int usageindex)
    {
        this.l = l;
        this.n = n;
        this.certainty = certainty;
        this.usageindex = usageindex;
        this.random = random;
    }

    public int getl()
    {
        return l;
    }

    public int getn()
    {
        return n;
    }

    public int getcertainty()
    {
        return certainty;
    }

    public securerandom getrandom()
    {
        return random;
    }

    public int getusageindex()
    {
        return usageindex;
    }
}
