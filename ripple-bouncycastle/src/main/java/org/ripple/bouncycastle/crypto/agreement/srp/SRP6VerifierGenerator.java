package org.ripple.bouncycastle.crypto.agreement.srp;

import java.math.biginteger;

import org.ripple.bouncycastle.crypto.digest;

/**
 * generates new srp verifier for user
 */
public class srp6verifiergenerator
{
    protected biginteger n;
    protected biginteger g;
    protected digest digest;

    public srp6verifiergenerator()
    {
    }

    /**
     * initialises generator to create new verifiers
     * @param n the safe prime to use (see dhparametersgenerator)
     * @param g the group parameter to use (see dhparametersgenerator)
     * @param digest the digest to use. the same digest type will need to be used later for the actual authentication
     * attempt. also note that the final session key size is dependent on the chosen digest.
     */
    public void init(biginteger n, biginteger g, digest digest)
    {
        this.n = n;
        this.g = g;
        this.digest = digest;
    }

    /**
     * creates a new srp verifier
     * @param salt the salt to use, generally should be large and random
     * @param identity the user's identifying information (eg. username)
     * @param password the user's password
     * @return a new verifier for use in future srp authentication
     */
    public biginteger generateverifier(byte[] salt, byte[] identity, byte[] password)
    {
        biginteger x = srp6util.calculatex(digest, n, salt, identity, password);

        return g.modpow(x, n);
    }
}
