package org.ripple.bouncycastle.crypto.agreement.jpake;

import java.math.biginteger;

/**
 * a pre-computed prime order group for use during a j-pake exchange.
 * <p/>
 * <p/>
 * typically a schnorr group is used.  in general, j-pake can use any prime order group
 * that is suitable for public key cryptography, including elliptic curve cryptography.
 * <p/>
 * <p/>
 * see {@link jpakeprimeordergroups} for convenient standard groups.
 * <p/>
 * <p/>
 * nist <a href="http://csrc.nist.gov/groups/st/toolkit/documents/examples/dsa2_all.pdf">publishes</a>
 * many groups that can be used for the desired level of security.
 */
public class jpakeprimeordergroup
{
    private final biginteger p;
    private final biginteger q;
    private final biginteger g;

    /**
     * constructs a new {@link jpakeprimeordergroup}.
     * <p/>
     * <p/>
     * in general, you should use one of the pre-approved groups from
     * {@link jpakeprimeordergroups}, rather than manually constructing one.
     * <p/>
     * <p/>
     * the following basic checks are performed:
     * <ul>
     * <li>p-1 must be evenly divisible by q</li>
     * <li>g must be in [2, p-1]</li>
     * <li>g^q mod p must equal 1</li>
     * <li>p must be prime (within reasonably certainty)</li>
     * <li>q must be prime (within reasonably certainty)</li>
     * </ul>
     * <p/>
     * <p/>
     * the prime checks are performed using {@link biginteger#isprobableprime(int)},
     * and are therefore subject to the same probability guarantees.
     * <p/>
     * <p/>
     * these checks prevent trivial mistakes.
     * however, due to the small uncertainties if p and q are not prime,
     * advanced attacks are not prevented.
     * use it at your own risk.
     *
     * @throws nullpointerexception if any argument is null
     * @throws illegalargumentexception if any of the above validations fail
     */
    public jpakeprimeordergroup(biginteger p, biginteger q, biginteger g)
    {
        /*
         * don't skip the checks on user-specified groups.
         */
        this(p, q, g, false);
    }

    /**
     * internal package-private constructor used by the pre-approved
     * groups in {@link jpakeprimeordergroups}.
     * these pre-approved groups can avoid the expensive checks.
     */
    jpakeprimeordergroup(biginteger p, biginteger q, biginteger g, boolean skipchecks)
    {
        jpakeutil.validatenotnull(p, "p");
        jpakeutil.validatenotnull(q, "q");
        jpakeutil.validatenotnull(g, "g");

        if (!skipchecks)
        {
            if (!p.subtract(jpakeutil.one).mod(q).equals(jpakeutil.zero))
            {
                throw new illegalargumentexception("p-1 must be evenly divisible by q");
            }
            if (g.compareto(biginteger.valueof(2)) == -1 || g.compareto(p.subtract(jpakeutil.one)) == 1)
            {
                throw new illegalargumentexception("g must be in [2, p-1]");
            }
            if (!g.modpow(q, p).equals(jpakeutil.one))
            {
                throw new illegalargumentexception("g^q mod p must equal 1");
            }
            /*
             * note that these checks do not guarantee that p and q are prime.
             * we just have reasonable certainty that they are prime.
             */
            if (!p.isprobableprime(20))
            {
                throw new illegalargumentexception("p must be prime");
            }
            if (!q.isprobableprime(20))
            {
                throw new illegalargumentexception("q must be prime");
            }
        }

        this.p = p;
        this.q = q;
        this.g = g;
    }

    public biginteger getp()
    {
        return p;
    }

    public biginteger getq()
    {
        return q;
    }

    public biginteger getg()
    {
        return g;
    }

}
