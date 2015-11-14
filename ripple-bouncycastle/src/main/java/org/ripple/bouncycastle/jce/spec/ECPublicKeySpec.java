package org.ripple.bouncycastle.jce.spec;

import org.ripple.bouncycastle.math.ec.ecpoint;

/**
 * elliptic curve public key specification
 */
public class ecpublickeyspec
    extends eckeyspec
{
    private ecpoint    q;

    /**
     * base constructor
     *
     * @param q the public point on the curve.
     * @param spec the domain parameters for the curve.
     */
    public ecpublickeyspec(
        ecpoint         q,
        ecparameterspec spec)
    {
        super(spec);

        this.q = q;
    }

    /**
     * return the public point q
     */
    public ecpoint getq()
    {
        return q;
    }
}
