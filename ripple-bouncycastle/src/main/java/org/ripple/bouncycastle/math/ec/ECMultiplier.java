package org.ripple.bouncycastle.math.ec;

import java.math.biginteger;

/**
 * interface for classes encapsulating a point multiplication algorithm
 * for <code>ecpoint</code>s.
 */
interface ecmultiplier
{
    /**
     * multiplies the <code>ecpoint p</code> by <code>k</code>, i.e.
     * <code>p</code> is added <code>k</code> times to itself.
     * @param p the <code>ecpoint</code> to be multiplied.
     * @param k the factor by which <code>p</code> i multiplied.
     * @return <code>p</code> multiplied by <code>k</code>.
     */
    ecpoint multiply(ecpoint p, biginteger k, precompinfo precompinfo);
}
