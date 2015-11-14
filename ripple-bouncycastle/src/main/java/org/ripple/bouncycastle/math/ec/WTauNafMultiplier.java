package org.ripple.bouncycastle.math.ec;

import java.math.biginteger;

/**
 * class implementing the wtnaf (window
 * <code>&tau;</code>-adic non-adjacent form) algorithm.
 */
class wtaunafmultiplier implements ecmultiplier
{
    /**
     * multiplies a {@link org.ripple.bouncycastle.math.ec.ecpoint.f2m ecpoint.f2m}
     * by <code>k</code> using the reduced <code>&tau;</code>-adic naf (rtnaf)
     * method.
     * @param p the ecpoint.f2m to multiply.
     * @param k the integer by which to multiply <code>k</code>.
     * @return <code>p</code> multiplied by <code>k</code>.
     */
    public ecpoint multiply(ecpoint point, biginteger k, precompinfo precompinfo)
    {
        if (!(point instanceof ecpoint.f2m))
        {
            throw new illegalargumentexception("only ecpoint.f2m can be " +
                    "used in wtaunafmultiplier");
        }

        ecpoint.f2m p = (ecpoint.f2m)point;

        eccurve.f2m curve = (eccurve.f2m) p.getcurve();
        int m = curve.getm();
        byte a = curve.geta().tobiginteger().bytevalue();
        byte mu = curve.getmu();
        biginteger[] s = curve.getsi();

        ztauelement rho = tnaf.partmodreduction(k, m, a, s, mu, (byte)10);

        return multiplywtnaf(p, rho, precompinfo, a, mu);
    }

    /**
     * multiplies a {@link org.ripple.bouncycastle.math.ec.ecpoint.f2m ecpoint.f2m}
     * by an element <code>&lambda;</code> of <code><b>z</b>[&tau;]</code> using
     * the <code>&tau;</code>-adic naf (tnaf) method.
     * @param p the ecpoint.f2m to multiply.
     * @param lambda the element <code>&lambda;</code> of
     * <code><b>z</b>[&tau;]</code> of which to compute the
     * <code>[&tau;]</code>-adic naf.
     * @return <code>p</code> multiplied by <code>&lambda;</code>.
     */
    private ecpoint.f2m multiplywtnaf(ecpoint.f2m p, ztauelement lambda,
            precompinfo precompinfo, byte a, byte mu)
    {
        ztauelement[] alpha;
        if (a == 0)
        {
            alpha = tnaf.alpha0;
        }
        else
        {
            // a == 1
            alpha = tnaf.alpha1;
        }

        biginteger tw = tnaf.gettw(mu, tnaf.width);

        byte[]u = tnaf.tauadicwnaf(mu, lambda, tnaf.width,
                biginteger.valueof(tnaf.pow_2_width), tw, alpha);

        return multiplyfromwtnaf(p, u, precompinfo);
    }

    /**
     * multiplies a {@link org.ripple.bouncycastle.math.ec.ecpoint.f2m ecpoint.f2m}
     * by an element <code>&lambda;</code> of <code><b>z</b>[&tau;]</code>
     * using the window <code>&tau;</code>-adic naf (tnaf) method, given the
     * wtnaf of <code>&lambda;</code>.
     * @param p the ecpoint.f2m to multiply.
     * @param u the the wtnaf of <code>&lambda;</code>..
     * @return <code>&lambda; * p</code>
     */
    private static ecpoint.f2m multiplyfromwtnaf(ecpoint.f2m p, byte[] u,
            precompinfo precompinfo)
    {
        eccurve.f2m curve = (eccurve.f2m)p.getcurve();
        byte a = curve.geta().tobiginteger().bytevalue();

        ecpoint.f2m[] pu;
        if ((precompinfo == null) || !(precompinfo instanceof wtaunafprecompinfo))
        {
            pu = tnaf.getprecomp(p, a);
            p.setprecompinfo(new wtaunafprecompinfo(pu));
        }
        else
        {
            pu = ((wtaunafprecompinfo)precompinfo).getprecomp();
        }

        // q = infinity
        ecpoint.f2m q = (ecpoint.f2m) p.getcurve().getinfinity();
        for (int i = u.length - 1; i >= 0; i--)
        {
            q = tnaf.tau(q);
            if (u[i] != 0)
            {
                if (u[i] > 0)
                {
                    q = q.addsimple(pu[u[i]]);
                }
                else
                {
                    // u[i] < 0
                    q = q.subtractsimple(pu[-u[i]]);
                }
            }
        }

        return q;
    }
}
