package org.ripple.bouncycastle.jce.spec;

import java.security.spec.algorithmparameterspec;

public class elgamalgenparameterspec
    implements algorithmparameterspec
{
    private int primesize;

    /*
     * @param primesize the size (in bits) of the prime modulus.
     */
    public elgamalgenparameterspec(
        int     primesize)
    {
        this.primesize = primesize;
    }

    /**
     * returns the size in bits of the prime modulus.
     *
     * @return the size in bits of the prime modulus
     */
    public int getprimesize()
    {
        return primesize;
    }
}
