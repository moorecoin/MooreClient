package org.ripple.bouncycastle.crypto.agreement.srp;

import java.math.biginteger;
import java.security.securerandom;

import org.ripple.bouncycastle.crypto.cryptoexception;
import org.ripple.bouncycastle.crypto.digest;

/**
 * implements the client side srp-6a protocol. note that this class is stateful, and therefore not threadsafe.
 * this implementation of srp is based on the optimized message sequence put forth by thomas wu in the paper
 * "srp-6: improvements and refinements to the secure remote password protocol, 2002"
 */
public class srp6client
{
    protected biginteger n;
    protected biginteger g;

    protected biginteger a;
    protected biginteger a;

    protected biginteger b;

    protected biginteger x;
    protected biginteger u;
    protected biginteger s;

    protected digest digest;
    protected securerandom random;

    public srp6client()
    {
    }

    /**
     * initialises the client to begin new authentication attempt
     * @param n the safe prime associated with the client's verifier
     * @param g the group parameter associated with the client's verifier
     * @param digest the digest algorithm associated with the client's verifier
     * @param random for key generation
     */
    public void init(biginteger n, biginteger g, digest digest, securerandom random)
    {
        this.n = n;
        this.g = g;
        this.digest = digest;
        this.random = random;
    }

    /**
     * generates client's credentials given the client's salt, identity and password
     * @param salt the salt used in the client's verifier.
     * @param identity the user's identity (eg. username)
     * @param password the user's password
     * @return client's public value to send to server
     */
    public biginteger generateclientcredentials(byte[] salt, byte[] identity, byte[] password)
    {
        this.x = srp6util.calculatex(digest, n, salt, identity, password);
        this.a = selectprivatevalue();
        this.a = g.modpow(a, n);

        return a;
    }

    /**
     * generates client's verification message given the server's credentials
     * @param serverb the server's credentials
     * @return client's verification message for the server
     * @throws cryptoexception if server's credentials are invalid
     */
    public biginteger calculatesecret(biginteger serverb) throws cryptoexception
    {
        this.b = srp6util.validatepublicvalue(n, serverb);
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
        biginteger k = srp6util.calculatek(digest, n, g);
        biginteger exp = u.multiply(x).add(a);
        biginteger tmp = g.modpow(x, n).multiply(k).mod(n);
        return b.subtract(tmp).mod(n).modpow(exp, n);
    }
}
