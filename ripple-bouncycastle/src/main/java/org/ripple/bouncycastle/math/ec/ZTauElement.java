package org.ripple.bouncycastle.math.ec;

import java.math.biginteger;

/**
 * class representing an element of <code><b>z</b>[&tau;]</code>. let
 * <code>&lambda;</code> be an element of <code><b>z</b>[&tau;]</code>. then
 * <code>&lambda;</code> is given as <code>&lambda; = u + v&tau;</code>. the
 * components <code>u</code> and <code>v</code> may be used directly, there
 * are no accessor methods.
 * immutable class.
 */
class ztauelement
{
    /**
     * the &quot;real&quot; part of <code>&lambda;</code>.
     */
    public final biginteger u;

    /**
     * the &quot;<code>&tau;</code>-adic&quot; part of <code>&lambda;</code>.
     */
    public final biginteger v;

    /**
     * constructor for an element <code>&lambda;</code> of
     * <code><b>z</b>[&tau;]</code>.
     * @param u the &quot;real&quot; part of <code>&lambda;</code>.
     * @param v the &quot;<code>&tau;</code>-adic&quot; part of
     * <code>&lambda;</code>.
     */
    public ztauelement(biginteger u, biginteger v)
    {
        this.u = u;
        this.v = v;
    }
}
