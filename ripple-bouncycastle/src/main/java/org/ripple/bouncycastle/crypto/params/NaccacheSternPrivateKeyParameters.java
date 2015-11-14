package org.ripple.bouncycastle.crypto.params;

import java.math.biginteger;
import java.util.vector;

/**
 * private key parameters for naccachestern cipher. for details on this cipher,
 * please see
 * 
 * http://www.gemplus.com/smart/rd/publications/pdf/ns98pkcs.pdf
 */
public class naccachesternprivatekeyparameters extends naccachesternkeyparameters 
{
    private biginteger phi_n;
    private vector     smallprimes;

    /**
     * constructs a naccachesternprivatekey
     * 
     * @param g
     *            the public enryption parameter g
     * @param n
     *            the public modulus n = p*q
     * @param lowersigmabound
     *            the public lower sigma bound up to which data can be encrypted
     * @param smallprimes
     *            the small primes, of which sigma is constructed in the right
     *            order
     * @param phi_n
     *            the private modulus phi(n) = (p-1)(q-1)
     */
    public naccachesternprivatekeyparameters(biginteger g, biginteger n,
            int lowersigmabound, vector smallprimes,
            biginteger phi_n)
    {
        super(true, g, n, lowersigmabound);
        this.smallprimes = smallprimes;
        this.phi_n = phi_n;
    }

    public biginteger getphi_n()
    {
        return phi_n;
    }

    public vector getsmallprimes()
    {
        return smallprimes;
    }
}
