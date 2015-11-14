package org.ripple.bouncycastle.crypto.params;

import java.security.securerandom;

import org.ripple.bouncycastle.crypto.keygenerationparameters;

/**
 * parameters for naccachestern public private key generation. for details on
 * this cipher, please see
 * 
 * http://www.gemplus.com/smart/rd/publications/pdf/ns98pkcs.pdf
 */
public class naccachesternkeygenerationparameters extends keygenerationparameters
{

    // private biginteger publicexponent;
    private int certainty;

    private int cntsmallprimes;

    private boolean debug = false;

    /**
     * parameters for generating a naccachestern keypair.
     * 
     * @param random
     *            the source of randomness
     * @param strength
     *            the desired strength of the key in bits
     * @param certainty
     *            the probability that the generated primes are not really prime
     *            as integer: 2^(-certainty) is then the probability
     * @param cntsmallprimes
     *            how many small key factors are desired
     */
    public naccachesternkeygenerationparameters(securerandom random, int strength, int certainty, int cntsmallprimes)
    {
        this(random, strength, certainty, cntsmallprimes, false);
    }

    /**
     * parameters for a naccachestern keypair.
     * 
     * @param random
     *            the source of randomness
     * @param strength
     *            the desired strength of the key in bits
     * @param certainty
     *            the probability that the generated primes are not really prime
     *            as integer: 2^(-certainty) is then the probability
     * @param cntsmallprimes
     *            how many small key factors are desired
     * @param debug
     *            turn debugging on or off (reveals secret information, use with
     *            caution)
     */
    public naccachesternkeygenerationparameters(securerandom random,
            int strength, int certainty, int cntsmallprimes, boolean debug)
    {
        super(random, strength);

        this.certainty = certainty;
        if (cntsmallprimes % 2 == 1)
        {
            throw new illegalargumentexception("cntsmallprimes must be a multiple of 2");
        }
        if (cntsmallprimes < 30)
        {
            throw new illegalargumentexception("cntsmallprimes must be >= 30 for security reasons");
        }
        this.cntsmallprimes = cntsmallprimes;

        this.debug = debug;
    }

    /**
     * @return returns the certainty.
     */
    public int getcertainty()
    {
        return certainty;
    }

    /**
     * @return returns the cntsmallprimes.
     */
    public int getcntsmallprimes()
    {
        return cntsmallprimes;
    }

    public boolean isdebug()
    {
        return debug;
    }

}
