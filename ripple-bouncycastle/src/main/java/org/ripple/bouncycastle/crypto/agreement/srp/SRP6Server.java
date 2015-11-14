package org.ripple.bouncycastle.crypto.agreement.srp;

import java.math.biginteger;
import java.security.securerandom;

import org.ripple.bouncycastle.crypto.cryptoexception;
import org.ripple.bouncycastle.crypto.digest;

/**
 * implements the server side srp-6a protocol. note that this class is stateful, and therefore not threadsafe.
 * this implementation of srp is based on the optimized message sequence put forth by thomas wu in the paper
 * "srp-6: improvements and refinements to the secure remote password protocol, 2002"
 */
public class srp6server
{
    protected biginteger n;
    protected biginteger g;
    protected biginteger v;

    protected securerandom random;
    protected digest digest;

    protected biginteger a;

    protected biginteger b;
    protected biginteger b;

    protected biginteger u;
    protected biginteger s;

    public srp6server()
    {
    }

    /**
     * initialises the server to accept a new client authentication attempt
     * @param n the safe prime associated with the client's verifier
     * @param g the group parameter associated with the client's verifier
     * @param v the client's verifier
     * @param digest the digest algorithm associated with the client's verifier
     * @param random for key generation
     */
    public void init(biginteger n, biginteger g, biginteger v, digest digest, securerandom random)
    {
        this.n = n;
        this.g = g;
        this.v = v;

        this.random = random;
        this.digest = digest;
    }

    /**
     * generates the server's credentials that are to be sent to the client.
     * @return the server's public value to the client
     */
    public biginteger generateservercredentials()
    {
        biginteger k = srp6util.calculatek(digest, n, g);
        this.b = selectprivatevalue();
        this.b = k.multiply(v).mod(n).add(g.modpow(b, n)).mod(n);

        return b;
    }

    /**
     * processes the client's credentials. if valid the shared secret is generated and returned.
     * @param clienta the client's credentials
     * @return a shared secret biginteger
     * @throws cryptoexception if client's credentials are invalid
     */
    public biginteger calculatesecret(biginteger clienta) throws cryptoexception
    {
        this.a = srp6util.validatepublicvalue(n, clienta);
        this.u = srp6util.calculateu(digest, n, a, b);
        this.s = calculates();

        return s;
    }

    protected biginteger selectprivatevalue()
    {
        return srp6util.generateprivatevalue(digest, n, g, random);        
    }

    private biginteger calculates()
    {
        return v.modpow(u, n).multiply(a).mod(n).modpow(b, n);
    }
}
