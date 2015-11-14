package org.ripple.bouncycastle.math.ec;

import java.math.biginteger;

/**
 * class holding methods for point multiplication based on the window
 * &tau;-adic nonadjacent form (wtnaf). the algorithms are based on the
 * paper "improved algorithms for arithmetic on anomalous binary curves"
 * by jerome a. solinas. the paper first appeared in the proceedings of
 * crypto 1997.
 */
class tnaf
{
    private static final biginteger minus_one = ecconstants.one.negate();
    private static final biginteger minus_two = ecconstants.two.negate();
    private static final biginteger minus_three = ecconstants.three.negate();

    /**
     * the window width of wtnaf. the standard value of 4 is slightly less
     * than optimal for running time, but keeps space requirements for
     * precomputation low. for typical curves, a value of 5 or 6 results in
     * a better running time. when changing this value, the
     * <code>&alpha;<sub>u</sub></code>'s must be computed differently, see
     * e.g. "guide to elliptic curve cryptography", darrel hankerson,
     * alfred menezes, scott vanstone, springer-verlag new york inc., 2004,
     * p. 121-122
     */
    public static final byte width = 4;

    /**
     * 2<sup>4</sup>
     */
    public static final byte pow_2_width = 16;

    /**
     * the <code>&alpha;<sub>u</sub></code>'s for <code>a=0</code> as an array
     * of <code>ztauelement</code>s.
     */
    public static final ztauelement[] alpha0 = {
        null,
        new ztauelement(ecconstants.one, ecconstants.zero), null,
        new ztauelement(minus_three, minus_one), null,
        new ztauelement(minus_one, minus_one), null,
        new ztauelement(ecconstants.one, minus_one), null
    };

    /**
     * the <code>&alpha;<sub>u</sub></code>'s for <code>a=0</code> as an array
     * of tnafs.
     */
    public static final byte[][] alpha0tnaf = {
        null, {1}, null, {-1, 0, 1}, null, {1, 0, 1}, null, {-1, 0, 0, 1}
    };

    /**
     * the <code>&alpha;<sub>u</sub></code>'s for <code>a=1</code> as an array
     * of <code>ztauelement</code>s.
     */
    public static final ztauelement[] alpha1 = {null,
        new ztauelement(ecconstants.one, ecconstants.zero), null,
        new ztauelement(minus_three, ecconstants.one), null,
        new ztauelement(minus_one, ecconstants.one), null,
        new ztauelement(ecconstants.one, ecconstants.one), null
    };

    /**
     * the <code>&alpha;<sub>u</sub></code>'s for <code>a=1</code> as an array
     * of tnafs.
     */
    public static final byte[][] alpha1tnaf = {
        null, {1}, null, {-1, 0, 1}, null, {1, 0, 1}, null, {-1, 0, 0, -1}
    };

    /**
     * computes the norm of an element <code>&lambda;</code> of
     * <code><b>z</b>[&tau;]</code>.
     * @param mu the parameter <code>&mu;</code> of the elliptic curve.
     * @param lambda the element <code>&lambda;</code> of
     * <code><b>z</b>[&tau;]</code>.
     * @return the norm of <code>&lambda;</code>.
     */
    public static biginteger norm(final byte mu, ztauelement lambda)
    {
        biginteger norm;

        // s1 = u^2
        biginteger s1 = lambda.u.multiply(lambda.u);

        // s2 = u * v
        biginteger s2 = lambda.u.multiply(lambda.v);

        // s3 = 2 * v^2
        biginteger s3 = lambda.v.multiply(lambda.v).shiftleft(1);

        if (mu == 1)
        {
            norm = s1.add(s2).add(s3);
        }
        else if (mu == -1)
        {
            norm = s1.subtract(s2).add(s3);
        }
        else
        {
            throw new illegalargumentexception("mu must be 1 or -1");
        }

        return norm;
    }

    /**
     * computes the norm of an element <code>&lambda;</code> of
     * <code><b>r</b>[&tau;]</code>, where <code>&lambda; = u + v&tau;</code>
     * and <code>u</code> and <code>u</code> are real numbers (elements of
     * <code><b>r</b></code>). 
     * @param mu the parameter <code>&mu;</code> of the elliptic curve.
     * @param u the real part of the element <code>&lambda;</code> of
     * <code><b>r</b>[&tau;]</code>.
     * @param v the <code>&tau;</code>-adic part of the element
     * <code>&lambda;</code> of <code><b>r</b>[&tau;]</code>.
     * @return the norm of <code>&lambda;</code>.
     */
    public static simplebigdecimal norm(final byte mu, simplebigdecimal u,
            simplebigdecimal v)
    {
        simplebigdecimal norm;

        // s1 = u^2
        simplebigdecimal s1 = u.multiply(u);

        // s2 = u * v
        simplebigdecimal s2 = u.multiply(v);

        // s3 = 2 * v^2
        simplebigdecimal s3 = v.multiply(v).shiftleft(1);

        if (mu == 1)
        {
            norm = s1.add(s2).add(s3);
        }
        else if (mu == -1)
        {
            norm = s1.subtract(s2).add(s3);
        }
        else
        {
            throw new illegalargumentexception("mu must be 1 or -1");
        }

        return norm;
    }

    /**
     * rounds an element <code>&lambda;</code> of <code><b>r</b>[&tau;]</code>
     * to an element of <code><b>z</b>[&tau;]</code>, such that their difference
     * has minimal norm. <code>&lambda;</code> is given as
     * <code>&lambda; = &lambda;<sub>0</sub> + &lambda;<sub>1</sub>&tau;</code>.
     * @param lambda0 the component <code>&lambda;<sub>0</sub></code>.
     * @param lambda1 the component <code>&lambda;<sub>1</sub></code>.
     * @param mu the parameter <code>&mu;</code> of the elliptic curve. must
     * equal 1 or -1.
     * @return the rounded element of <code><b>z</b>[&tau;]</code>.
     * @throws illegalargumentexception if <code>lambda0</code> and
     * <code>lambda1</code> do not have same scale.
     */
    public static ztauelement round(simplebigdecimal lambda0,
            simplebigdecimal lambda1, byte mu)
    {
        int scale = lambda0.getscale();
        if (lambda1.getscale() != scale)
        {
            throw new illegalargumentexception("lambda0 and lambda1 do not " +
                    "have same scale");
        }

        if (!((mu == 1) || (mu == -1)))
        {
            throw new illegalargumentexception("mu must be 1 or -1");
        }

        biginteger f0 = lambda0.round();
        biginteger f1 = lambda1.round();

        simplebigdecimal eta0 = lambda0.subtract(f0);
        simplebigdecimal eta1 = lambda1.subtract(f1);

        // eta = 2*eta0 + mu*eta1
        simplebigdecimal eta = eta0.add(eta0);
        if (mu == 1)
        {
            eta = eta.add(eta1);
        }
        else
        {
            // mu == -1
            eta = eta.subtract(eta1);
        }

        // check1 = eta0 - 3*mu*eta1
        // check2 = eta0 + 4*mu*eta1
        simplebigdecimal threeeta1 = eta1.add(eta1).add(eta1);
        simplebigdecimal foureta1 = threeeta1.add(eta1);
        simplebigdecimal check1;
        simplebigdecimal check2;
        if (mu == 1)
        {
            check1 = eta0.subtract(threeeta1);
            check2 = eta0.add(foureta1);
        }
        else
        {
            // mu == -1
            check1 = eta0.add(threeeta1);
            check2 = eta0.subtract(foureta1);
        }

        byte h0 = 0;
        byte h1 = 0;

        // if eta >= 1
        if (eta.compareto(ecconstants.one) >= 0)
        {
            if (check1.compareto(minus_one) < 0)
            {
                h1 = mu;
            }
            else
            {
                h0 = 1;
            }
        }
        else
        {
            // eta < 1
            if (check2.compareto(ecconstants.two) >= 0)
            {
                h1 = mu;
            }
        }

        // if eta < -1
        if (eta.compareto(minus_one) < 0)
        {
            if (check1.compareto(ecconstants.one) >= 0)
            {
                h1 = (byte)-mu;
            }
            else
            {
                h0 = -1;
            }
        }
        else
        {
            // eta >= -1
            if (check2.compareto(minus_two) < 0)
            {
                h1 = (byte)-mu;
            }
        }

        biginteger q0 = f0.add(biginteger.valueof(h0));
        biginteger q1 = f1.add(biginteger.valueof(h1));
        return new ztauelement(q0, q1);
    }

    /**
     * approximate division by <code>n</code>. for an integer
     * <code>k</code>, the value <code>&lambda; = s k / n</code> is
     * computed to <code>c</code> bits of accuracy.
     * @param k the parameter <code>k</code>.
     * @param s the curve parameter <code>s<sub>0</sub></code> or
     * <code>s<sub>1</sub></code>.
     * @param vm the lucas sequence element <code>v<sub>m</sub></code>.
     * @param a the parameter <code>a</code> of the elliptic curve.
     * @param m the bit length of the finite field
     * <code><b>f</b><sub>m</sub></code>.
     * @param c the number of bits of accuracy, i.e. the scale of the returned
     * <code>simplebigdecimal</code>.
     * @return the value <code>&lambda; = s k / n</code> computed to
     * <code>c</code> bits of accuracy.
     */
    public static simplebigdecimal approximatedivisionbyn(biginteger k,
            biginteger s, biginteger vm, byte a, int m, int c)
    {
        int _k = (m + 5)/2 + c;
        biginteger ns = k.shiftright(m - _k - 2 + a);

        biginteger gs = s.multiply(ns);

        biginteger hs = gs.shiftright(m);

        biginteger js = vm.multiply(hs);

        biginteger gsplusjs = gs.add(js);
        biginteger ls = gsplusjs.shiftright(_k-c);
        if (gsplusjs.testbit(_k-c-1))
        {
            // round up
            ls = ls.add(ecconstants.one);
        }

        return new simplebigdecimal(ls, c);
    }

    /**
     * computes the <code>&tau;</code>-adic naf (non-adjacent form) of an
     * element <code>&lambda;</code> of <code><b>z</b>[&tau;]</code>.
     * @param mu the parameter <code>&mu;</code> of the elliptic curve.
     * @param lambda the element <code>&lambda;</code> of
     * <code><b>z</b>[&tau;]</code>.
     * @return the <code>&tau;</code>-adic naf of <code>&lambda;</code>.
     */
    public static byte[] tauadicnaf(byte mu, ztauelement lambda)
    {
        if (!((mu == 1) || (mu == -1)))
        {
            throw new illegalargumentexception("mu must be 1 or -1");
        }
        
        biginteger norm = norm(mu, lambda);

        // ceiling of log2 of the norm 
        int log2norm = norm.bitlength();

        // if length(tnaf) > 30, then length(tnaf) < log2norm + 3.52
        int maxlength = log2norm > 30 ? log2norm + 4 : 34;

        // the array holding the tnaf
        byte[] u = new byte[maxlength];
        int i = 0;

        // the actual length of the tnaf
        int length = 0;

        biginteger r0 = lambda.u;
        biginteger r1 = lambda.v;

        while(!((r0.equals(ecconstants.zero)) && (r1.equals(ecconstants.zero))))
        {
            // if r0 is odd
            if (r0.testbit(0))
            {
                u[i] = (byte) ecconstants.two.subtract((r0.subtract(r1.shiftleft(1))).mod(ecconstants.four)).intvalue();

                // r0 = r0 - u[i]
                if (u[i] == 1)
                {
                    r0 = r0.clearbit(0);
                }
                else
                {
                    // u[i] == -1
                    r0 = r0.add(ecconstants.one);
                }
                length = i;
            }
            else
            {
                u[i] = 0;
            }

            biginteger t = r0;
            biginteger s = r0.shiftright(1);
            if (mu == 1)
            {
                r0 = r1.add(s);
            }
            else
            {
                // mu == -1
                r0 = r1.subtract(s);
            }

            r1 = t.shiftright(1).negate();
            i++;
        }

        length++;

        // reduce the tnaf array to its actual length
        byte[] tnaf = new byte[length];
        system.arraycopy(u, 0, tnaf, 0, length);
        return tnaf;
    }

    /**
     * applies the operation <code>&tau;()</code> to an
     * <code>ecpoint.f2m</code>. 
     * @param p the ecpoint.f2m to which <code>&tau;()</code> is applied.
     * @return <code>&tau;(p)</code>
     */
    public static ecpoint.f2m tau(ecpoint.f2m p)
    {
        if (p.isinfinity())
        {
            return p;
        }

        ecfieldelement x = p.getx();
        ecfieldelement y = p.gety();

        return new ecpoint.f2m(p.getcurve(), x.square(), y.square(), p.iscompressed());
    }

    /**
     * returns the parameter <code>&mu;</code> of the elliptic curve.
     * @param curve the elliptic curve from which to obtain <code>&mu;</code>.
     * the curve must be a koblitz curve, i.e. <code>a</code> equals
     * <code>0</code> or <code>1</code> and <code>b</code> equals
     * <code>1</code>. 
     * @return <code>&mu;</code> of the elliptic curve.
     * @throws illegalargumentexception if the given eccurve is not a koblitz
     * curve.
     */
    public static byte getmu(eccurve.f2m curve)
    {
        biginteger a = curve.geta().tobiginteger();
        byte mu;

        if (a.equals(ecconstants.zero))
        {
            mu = -1;
        }
        else if (a.equals(ecconstants.one))
        {
            mu = 1;
        }
        else
        {
            throw new illegalargumentexception("no koblitz curve (abc), " +
                    "tnaf multiplication not possible");
        }
        return mu;
    }

    /**
     * calculates the lucas sequence elements <code>u<sub>k-1</sub></code> and
     * <code>u<sub>k</sub></code> or <code>v<sub>k-1</sub></code> and
     * <code>v<sub>k</sub></code>.
     * @param mu the parameter <code>&mu;</code> of the elliptic curve.
     * @param k the index of the second element of the lucas sequence to be
     * returned.
     * @param dov if set to true, computes <code>v<sub>k-1</sub></code> and
     * <code>v<sub>k</sub></code>, otherwise <code>u<sub>k-1</sub></code> and
     * <code>u<sub>k</sub></code>.
     * @return an array with 2 elements, containing <code>u<sub>k-1</sub></code>
     * and <code>u<sub>k</sub></code> or <code>v<sub>k-1</sub></code>
     * and <code>v<sub>k</sub></code>.
     */
    public static biginteger[] getlucas(byte mu, int k, boolean dov)
    {
        if (!((mu == 1) || (mu == -1)))
        {
            throw new illegalargumentexception("mu must be 1 or -1");
        }

        biginteger u0;
        biginteger u1;
        biginteger u2;

        if (dov)
        {
            u0 = ecconstants.two;
            u1 = biginteger.valueof(mu);
        }
        else
        {
            u0 = ecconstants.zero;
            u1 = ecconstants.one;
        }

        for (int i = 1; i < k; i++)
        {
            // u2 = mu*u1 - 2*u0;
            biginteger s = null;
            if (mu == 1)
            {
                s = u1;
            }
            else
            {
                // mu == -1
                s = u1.negate();
            }
            
            u2 = s.subtract(u0.shiftleft(1));
            u0 = u1;
            u1 = u2;
//            system.out.println(i + ": " + u2);
//            system.out.println();
        }

        biginteger[] retval = {u0, u1};
        return retval;
    }

    /**
     * computes the auxiliary value <code>t<sub>w</sub></code>. if the width is
     * 4, then for <code>mu = 1</code>, <code>t<sub>w</sub> = 6</code> and for
     * <code>mu = -1</code>, <code>t<sub>w</sub> = 10</code> 
     * @param mu the parameter <code>&mu;</code> of the elliptic curve.
     * @param w the window width of the wtnaf.
     * @return the auxiliary value <code>t<sub>w</sub></code>
     */
    public static biginteger gettw(byte mu, int w)
    {
        if (w == 4)
        {
            if (mu == 1)
            {
                return biginteger.valueof(6);
            }
            else
            {
                // mu == -1
                return biginteger.valueof(10);
            }
        }
        else
        {
            // for w <> 4, the values must be computed
            biginteger[] us = getlucas(mu, w, false);
            biginteger twotow = ecconstants.zero.setbit(w);
            biginteger u1invert = us[1].modinverse(twotow);
            biginteger tw;
            tw = ecconstants.two.multiply(us[0]).multiply(u1invert).mod(twotow);
//            system.out.println("mu = " + mu);
//            system.out.println("tw = " + tw);
            return tw;
        }
    }

    /**
     * computes the auxiliary values <code>s<sub>0</sub></code> and
     * <code>s<sub>1</sub></code> used for partial modular reduction. 
     * @param curve the elliptic curve for which to compute
     * <code>s<sub>0</sub></code> and <code>s<sub>1</sub></code>.
     * @throws illegalargumentexception if <code>curve</code> is not a
     * koblitz curve (anomalous binary curve, abc).
     */
    public static biginteger[] getsi(eccurve.f2m curve)
    {
        if (!curve.iskoblitz())
        {
            throw new illegalargumentexception("si is defined for koblitz curves only");
        }

        int m = curve.getm();
        int a = curve.geta().tobiginteger().intvalue();
        byte mu = curve.getmu();
        int h = curve.geth().intvalue();
        int index = m + 3 - a;
        biginteger[] ui = getlucas(mu, index, false);

        biginteger dividend0;
        biginteger dividend1;
        if (mu == 1)
        {
            dividend0 = ecconstants.one.subtract(ui[1]);
            dividend1 = ecconstants.one.subtract(ui[0]);
        }
        else if (mu == -1)
        {
            dividend0 = ecconstants.one.add(ui[1]);
            dividend1 = ecconstants.one.add(ui[0]);
        }
        else
        {
            throw new illegalargumentexception("mu must be 1 or -1");
        }

        biginteger[] si = new biginteger[2];

        if (h == 2)
        {
            si[0] = dividend0.shiftright(1);
            si[1] = dividend1.shiftright(1).negate();
        }
        else if (h == 4)
        {
            si[0] = dividend0.shiftright(2);
            si[1] = dividend1.shiftright(2).negate();
        }
        else
        {
            throw new illegalargumentexception("h (cofactor) must be 2 or 4");
        }

        return si;
    }

    /**
     * partial modular reduction modulo
     * <code>(&tau;<sup>m</sup> - 1)/(&tau; - 1)</code>.
     * @param k the integer to be reduced.
     * @param m the bitlength of the underlying finite field.
     * @param a the parameter <code>a</code> of the elliptic curve.
     * @param s the auxiliary values <code>s<sub>0</sub></code> and
     * <code>s<sub>1</sub></code>.
     * @param mu the parameter &mu; of the elliptic curve.
     * @param c the precision (number of bits of accuracy) of the partial
     * modular reduction.
     * @return <code>&rho; := k partmod (&tau;<sup>m</sup> - 1)/(&tau; - 1)</code>
     */
    public static ztauelement partmodreduction(biginteger k, int m, byte a,
            biginteger[] s, byte mu, byte c)
    {
        // d0 = s[0] + mu*s[1]; mu is either 1 or -1
        biginteger d0;
        if (mu == 1)
        {
            d0 = s[0].add(s[1]);
        }
        else
        {
            d0 = s[0].subtract(s[1]);
        }

        biginteger[] v = getlucas(mu, m, true);
        biginteger vm = v[1];

        simplebigdecimal lambda0 = approximatedivisionbyn(
                k, s[0], vm, a, m, c);
        
        simplebigdecimal lambda1 = approximatedivisionbyn(
                k, s[1], vm, a, m, c);

        ztauelement q = round(lambda0, lambda1, mu);

        // r0 = n - d0*q0 - 2*s1*q1
        biginteger r0 = k.subtract(d0.multiply(q.u)).subtract(
                biginteger.valueof(2).multiply(s[1]).multiply(q.v));

        // r1 = s1*q0 - s0*q1
        biginteger r1 = s[1].multiply(q.u).subtract(s[0].multiply(q.v));
        
        return new ztauelement(r0, r1);
    }

    /**
     * multiplies a {@link org.ripple.bouncycastle.math.ec.ecpoint.f2m ecpoint.f2m}
     * by a <code>biginteger</code> using the reduced <code>&tau;</code>-adic
     * naf (rtnaf) method.
     * @param p the ecpoint.f2m to multiply.
     * @param k the <code>biginteger</code> by which to multiply <code>p</code>.
     * @return <code>k * p</code>
     */
    public static ecpoint.f2m multiplyrtnaf(ecpoint.f2m p, biginteger k)
    {
        eccurve.f2m curve = (eccurve.f2m) p.getcurve();
        int m = curve.getm();
        byte a = (byte) curve.geta().tobiginteger().intvalue();
        byte mu = curve.getmu();
        biginteger[] s = curve.getsi();
        ztauelement rho = partmodreduction(k, m, a, s, mu, (byte)10);

        return multiplytnaf(p, rho);
    }

    /**
     * multiplies a {@link org.ripple.bouncycastle.math.ec.ecpoint.f2m ecpoint.f2m}
     * by an element <code>&lambda;</code> of <code><b>z</b>[&tau;]</code>
     * using the <code>&tau;</code>-adic naf (tnaf) method.
     * @param p the ecpoint.f2m to multiply.
     * @param lambda the element <code>&lambda;</code> of
     * <code><b>z</b>[&tau;]</code>.
     * @return <code>&lambda; * p</code>
     */
    public static ecpoint.f2m multiplytnaf(ecpoint.f2m p, ztauelement lambda)
    {
        eccurve.f2m curve = (eccurve.f2m)p.getcurve();
        byte mu = curve.getmu();
        byte[] u = tauadicnaf(mu, lambda);

        ecpoint.f2m q = multiplyfromtnaf(p, u);

        return q;
    }

    /**
    * multiplies a {@link org.ripple.bouncycastle.math.ec.ecpoint.f2m ecpoint.f2m}
    * by an element <code>&lambda;</code> of <code><b>z</b>[&tau;]</code>
    * using the <code>&tau;</code>-adic naf (tnaf) method, given the tnaf
    * of <code>&lambda;</code>.
    * @param p the ecpoint.f2m to multiply.
    * @param u the the tnaf of <code>&lambda;</code>..
    * @return <code>&lambda; * p</code>
    */
    public static ecpoint.f2m multiplyfromtnaf(ecpoint.f2m p, byte[] u)
    {
        eccurve.f2m curve = (eccurve.f2m)p.getcurve();
        ecpoint.f2m q = (ecpoint.f2m) curve.getinfinity();
        for (int i = u.length - 1; i >= 0; i--)
        {
            q = tau(q);
            if (u[i] == 1)
            {
                q = (ecpoint.f2m)q.addsimple(p);
            }
            else if (u[i] == -1)
            {
                q = (ecpoint.f2m)q.subtractsimple(p);
            }
        }
        return q;
    }

    /**
     * computes the <code>[&tau;]</code>-adic window naf of an element
     * <code>&lambda;</code> of <code><b>z</b>[&tau;]</code>.
     * @param mu the parameter &mu; of the elliptic curve.
     * @param lambda the element <code>&lambda;</code> of
     * <code><b>z</b>[&tau;]</code> of which to compute the
     * <code>[&tau;]</code>-adic naf.
     * @param width the window width of the resulting wnaf.
     * @param pow2w 2<sup>width</sup>.
     * @param tw the auxiliary value <code>t<sub>w</sub></code>.
     * @param alpha the <code>&alpha;<sub>u</sub></code>'s for the window width.
     * @return the <code>[&tau;]</code>-adic window naf of
     * <code>&lambda;</code>.
     */
    public static byte[] tauadicwnaf(byte mu, ztauelement lambda,
            byte width, biginteger pow2w, biginteger tw, ztauelement[] alpha)
    {
        if (!((mu == 1) || (mu == -1)))
        {
            throw new illegalargumentexception("mu must be 1 or -1");
        }

        biginteger norm = norm(mu, lambda);

        // ceiling of log2 of the norm 
        int log2norm = norm.bitlength();

        // if length(tnaf) > 30, then length(tnaf) < log2norm + 3.52
        int maxlength = log2norm > 30 ? log2norm + 4 + width : 34 + width;

        // the array holding the tnaf
        byte[] u = new byte[maxlength];

        // 2^(width - 1)
        biginteger pow2wmin1 = pow2w.shiftright(1);

        // split lambda into two bigintegers to simplify calculations
        biginteger r0 = lambda.u;
        biginteger r1 = lambda.v;
        int i = 0;

        // while lambda <> (0, 0)
        while (!((r0.equals(ecconstants.zero))&&(r1.equals(ecconstants.zero))))
        {
            // if r0 is odd
            if (r0.testbit(0))
            {
                // uunmod = r0 + r1*tw mod 2^width
                biginteger uunmod
                    = r0.add(r1.multiply(tw)).mod(pow2w);
                
                byte ulocal;
                // if uunmod >= 2^(width - 1)
                if (uunmod.compareto(pow2wmin1) >= 0)
                {
                    ulocal = (byte) uunmod.subtract(pow2w).intvalue();
                }
                else
                {
                    ulocal = (byte) uunmod.intvalue();
                }
                // ulocal is now in [-2^(width-1), 2^(width-1)-1]

                u[i] = ulocal;
                boolean s = true;
                if (ulocal < 0)
                {
                    s = false;
                    ulocal = (byte)-ulocal;
                }
                // ulocal is now >= 0

                if (s)
                {
                    r0 = r0.subtract(alpha[ulocal].u);
                    r1 = r1.subtract(alpha[ulocal].v);
                }
                else
                {
                    r0 = r0.add(alpha[ulocal].u);
                    r1 = r1.add(alpha[ulocal].v);
                }
            }
            else
            {
                u[i] = 0;
            }

            biginteger t = r0;

            if (mu == 1)
            {
                r0 = r1.add(r0.shiftright(1));
            }
            else
            {
                // mu == -1
                r0 = r1.subtract(r0.shiftright(1));
            }
            r1 = t.shiftright(1).negate();
            i++;
        }
        return u;
    }

    /**
     * does the precomputation for wtnaf multiplication.
     * @param p the <code>ecpoint</code> for which to do the precomputation.
     * @param a the parameter <code>a</code> of the elliptic curve.
     * @return the precomputation array for <code>p</code>. 
     */
    public static ecpoint.f2m[] getprecomp(ecpoint.f2m p, byte a)
    {
        ecpoint.f2m[] pu;
        pu = new ecpoint.f2m[16];
        pu[1] = p;
        byte[][] alphatnaf;
        if (a == 0)
        {
            alphatnaf = tnaf.alpha0tnaf;
        }
        else
        {
            // a == 1
            alphatnaf = tnaf.alpha1tnaf;
        }

        int precomplen = alphatnaf.length;
        for (int i = 3; i < precomplen; i = i + 2)
        {
            pu[i] = tnaf.multiplyfromtnaf(p, alphatnaf[i]);
        }
        
        return pu;
    }
}
