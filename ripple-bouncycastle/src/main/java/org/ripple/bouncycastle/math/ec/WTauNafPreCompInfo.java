package org.ripple.bouncycastle.math.ec;

/**
 * class holding precomputation data for the wtnaf (window
 * <code>&tau;</code>-adic non-adjacent form) algorithm.
 */
class wtaunafprecompinfo implements precompinfo
{
    /**
     * array holding the precomputed <code>ecpoint.f2m</code>s used for the
     * wtnaf multiplication in <code>
     * {@link org.bouncycastle.math.ec.multiplier.wtaunafmultiplier.multiply()
     * wtaunafmultiplier.multiply()}</code>.
     */
    private ecpoint.f2m[] precomp = null;

    /**
     * constructor for <code>wtaunafprecompinfo</code>
     * @param precomp array holding the precomputed <code>ecpoint.f2m</code>s
     * used for the wtnaf multiplication in <code>
     * {@link org.bouncycastle.math.ec.multiplier.wtaunafmultiplier.multiply()
     * wtaunafmultiplier.multiply()}</code>.
     */
    wtaunafprecompinfo(ecpoint.f2m[] precomp)
    {
        this.precomp = precomp;
    }

    /**
     * @return the array holding the precomputed <code>ecpoint.f2m</code>s
     * used for the wtnaf multiplication in <code>
     * {@link org.bouncycastle.math.ec.multiplier.wtaunafmultiplier.multiply()
     * wtaunafmultiplier.multiply()}</code>.
     */
    protected ecpoint.f2m[] getprecomp()
    {
        return precomp;
    }
}
