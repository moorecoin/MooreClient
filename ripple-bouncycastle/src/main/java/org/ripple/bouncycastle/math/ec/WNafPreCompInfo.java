package org.ripple.bouncycastle.math.ec;

/**
 * class holding precomputation data for the wnaf (window non-adjacent form)
 * algorithm.
 */
class wnafprecompinfo implements precompinfo
{
    /**
     * array holding the precomputed <code>ecpoint</code>s used for the window
     * naf multiplication in <code>
     * {@link org.bouncycastle.math.ec.multiplier.wnafmultiplier.multiply()
     * wnafmultiplier.multiply()}</code>.
     */
    private ecpoint[] precomp = null;

    /**
     * holds an <code>ecpoint</code> representing twice(this). used for the
     * window naf multiplication in <code>
     * {@link org.bouncycastle.math.ec.multiplier.wnafmultiplier.multiply()
     * wnafmultiplier.multiply()}</code>.
     */
    private ecpoint twicep = null;

    protected ecpoint[] getprecomp()
    {
        return precomp;
    }

    protected void setprecomp(ecpoint[] precomp)
    {
        this.precomp = precomp;
    }

    protected ecpoint gettwicep()
    {
        return twicep;
    }

    protected void settwicep(ecpoint twicethis)
    {
        this.twicep = twicethis;
    }
}
