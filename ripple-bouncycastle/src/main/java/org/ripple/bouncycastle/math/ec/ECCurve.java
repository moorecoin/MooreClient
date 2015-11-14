package org.ripple.bouncycastle.math.ec;

import java.math.biginteger;
import java.util.random;

/**
 * base class for an elliptic curve
 */
public abstract class eccurve
{
    ecfieldelement a, b;

    public abstract int getfieldsize();

    public abstract ecfieldelement frombiginteger(biginteger x);

    public abstract ecpoint createpoint(biginteger x, biginteger y, boolean withcompression);

    public abstract ecpoint getinfinity();

    public ecfieldelement geta()
    {
        return a;
    }

    public ecfieldelement getb()
    {
        return b;
    }

    protected abstract ecpoint decompresspoint(int ytilde, biginteger x1);

    /**
     * decode a point on this curve from its asn.1 encoding. the different
     * encodings are taken account of, including point compression for
     * <code>f<sub>p</sub></code> (x9.62 s 4.2.1 pg 17).
     * @return the decoded point.
     */
    public ecpoint decodepoint(byte[] encoded)
    {
        ecpoint p = null;
        int expectedlength = (getfieldsize() + 7) / 8;

        switch (encoded[0])
        {
        case 0x00: // infinity
        {
            if (encoded.length != 1)
            {
                throw new illegalargumentexception("incorrect length for infinity encoding");
            }

            p = getinfinity();
            break;
        }
        case 0x02: // compressed
        case 0x03: // compressed
        {
            if (encoded.length != (expectedlength + 1))
            {
                throw new illegalargumentexception("incorrect length for compressed encoding");
            }

            int ytilde = encoded[0] & 1;
            biginteger x1 = fromarray(encoded, 1, expectedlength);

            p = decompresspoint(ytilde, x1);
            break;
        }
        case 0x04: // uncompressed
        case 0x06: // hybrid
        case 0x07: // hybrid
        {
            if (encoded.length != (2 * expectedlength + 1))
            {
                throw new illegalargumentexception("incorrect length for uncompressed/hybrid encoding");
            }

            biginteger x1 = fromarray(encoded, 1, expectedlength);
            biginteger y1 = fromarray(encoded, 1 + expectedlength, expectedlength);

            p = createpoint(x1, y1, false);
            break;
        }
        default:
            throw new illegalargumentexception("invalid point encoding 0x" + integer.tostring(encoded[0], 16));
        }

        return p;
    }

    private static biginteger fromarray(byte[] buf, int off, int length)
    {
        byte[] mag = new byte[length];
        system.arraycopy(buf, off, mag, 0, length);
        return new biginteger(1, mag);
    }

    /**
     * elliptic curve over fp
     */
    public static class fp extends eccurve
    {
        biginteger q;
        ecpoint.fp infinity;

        public fp(biginteger q, biginteger a, biginteger b)
        {
            this.q = q;
            this.a = frombiginteger(a);
            this.b = frombiginteger(b);
            this.infinity = new ecpoint.fp(this, null, null);
        }

        public biginteger getq()
        {
            return q;
        }

        public int getfieldsize()
        {
            return q.bitlength();
        }

        public ecfieldelement frombiginteger(biginteger x)
        {
            return new ecfieldelement.fp(this.q, x);
        }

        public ecpoint createpoint(biginteger x, biginteger y, boolean withcompression)
        {
            return new ecpoint.fp(this, frombiginteger(x), frombiginteger(y), withcompression);
        }

        protected ecpoint decompresspoint(int ytilde, biginteger x1)
        {
            ecfieldelement x = frombiginteger(x1);
            ecfieldelement alpha = x.multiply(x.square().add(a)).add(b);
            ecfieldelement beta = alpha.sqrt();

            //
            // if we can't find a sqrt we haven't got a point on the
            // curve - run!
            //
            if (beta == null)
            {
                throw new runtimeexception("invalid point compression");
            }

            biginteger betavalue = beta.tobiginteger();
            int bit0 = betavalue.testbit(0) ? 1 : 0;

            if (bit0 != ytilde)
            {
                // use the other root
                beta = frombiginteger(q.subtract(betavalue));
            }

            return new ecpoint.fp(this, x, beta, true);
        }

        public ecpoint getinfinity()
        {
            return infinity;
        }

        public boolean equals(
            object anobject) 
        {
            if (anobject == this) 
            {
                return true;
            }

            if (!(anobject instanceof eccurve.fp)) 
            {
                return false;
            }

            eccurve.fp other = (eccurve.fp) anobject;

            return this.q.equals(other.q) 
                    && a.equals(other.a) && b.equals(other.b);
        }

        public int hashcode() 
        {
            return a.hashcode() ^ b.hashcode() ^ q.hashcode();
        }
    }

    /**
     * elliptic curves over f2m. the weierstrass equation is given by
     * <code>y<sup>2</sup> + xy = x<sup>3</sup> + ax<sup>2</sup> + b</code>.
     */
    public static class f2m extends eccurve
    {
        /**
         * the exponent <code>m</code> of <code>f<sub>2<sup>m</sup></sub></code>.
         */
        private int m;  // can't be final - jdk 1.1

        /**
         * tpb: the integer <code>k</code> where <code>x<sup>m</sup> +
         * x<sup>k</sup> + 1</code> represents the reduction polynomial
         * <code>f(z)</code>.<br>
         * ppb: the integer <code>k1</code> where <code>x<sup>m</sup> +
         * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
         * represents the reduction polynomial <code>f(z)</code>.<br>
         */
        private int k1;  // can't be final - jdk 1.1

        /**
         * tpb: always set to <code>0</code><br>
         * ppb: the integer <code>k2</code> where <code>x<sup>m</sup> +
         * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
         * represents the reduction polynomial <code>f(z)</code>.<br>
         */
        private int k2;  // can't be final - jdk 1.1

        /**
         * tpb: always set to <code>0</code><br>
         * ppb: the integer <code>k3</code> where <code>x<sup>m</sup> +
         * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
         * represents the reduction polynomial <code>f(z)</code>.<br>
         */
        private int k3;  // can't be final - jdk 1.1

        /**
         * the order of the base point of the curve.
         */
        private biginteger n;  // can't be final - jdk 1.1

        /**
         * the cofactor of the curve.
         */
        private biginteger h;  // can't be final - jdk 1.1
        
         /**
         * the point at infinity on this curve.
         */
        private ecpoint.f2m infinity;  // can't be final - jdk 1.1

        /**
         * the parameter <code>&mu;</code> of the elliptic curve if this is
         * a koblitz curve.
         */
        private byte mu = 0;

        /**
         * the auxiliary values <code>s<sub>0</sub></code> and
         * <code>s<sub>1</sub></code> used for partial modular reduction for
         * koblitz curves.
         */
        private biginteger[] si = null;

        /**
         * constructor for trinomial polynomial basis (tpb).
         * @param m  the exponent <code>m</code> of
         * <code>f<sub>2<sup>m</sup></sub></code>.
         * @param k the integer <code>k</code> where <code>x<sup>m</sup> +
         * x<sup>k</sup> + 1</code> represents the reduction
         * polynomial <code>f(z)</code>.
         * @param a the coefficient <code>a</code> in the weierstrass equation
         * for non-supersingular elliptic curves over
         * <code>f<sub>2<sup>m</sup></sub></code>.
         * @param b the coefficient <code>b</code> in the weierstrass equation
         * for non-supersingular elliptic curves over
         * <code>f<sub>2<sup>m</sup></sub></code>.
         */
        public f2m(
            int m,
            int k,
            biginteger a,
            biginteger b)
        {
            this(m, k, 0, 0, a, b, null, null);
        }

        /**
         * constructor for trinomial polynomial basis (tpb).
         * @param m  the exponent <code>m</code> of
         * <code>f<sub>2<sup>m</sup></sub></code>.
         * @param k the integer <code>k</code> where <code>x<sup>m</sup> +
         * x<sup>k</sup> + 1</code> represents the reduction
         * polynomial <code>f(z)</code>.
         * @param a the coefficient <code>a</code> in the weierstrass equation
         * for non-supersingular elliptic curves over
         * <code>f<sub>2<sup>m</sup></sub></code>.
         * @param b the coefficient <code>b</code> in the weierstrass equation
         * for non-supersingular elliptic curves over
         * <code>f<sub>2<sup>m</sup></sub></code>.
         * @param n the order of the main subgroup of the elliptic curve.
         * @param h the cofactor of the elliptic curve, i.e.
         * <code>#e<sub>a</sub>(f<sub>2<sup>m</sup></sub>) = h * n</code>.
         */
        public f2m(
            int m, 
            int k, 
            biginteger a, 
            biginteger b,
            biginteger n,
            biginteger h)
        {
            this(m, k, 0, 0, a, b, n, h);
        }

        /**
         * constructor for pentanomial polynomial basis (ppb).
         * @param m  the exponent <code>m</code> of
         * <code>f<sub>2<sup>m</sup></sub></code>.
         * @param k1 the integer <code>k1</code> where <code>x<sup>m</sup> +
         * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
         * represents the reduction polynomial <code>f(z)</code>.
         * @param k2 the integer <code>k2</code> where <code>x<sup>m</sup> +
         * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
         * represents the reduction polynomial <code>f(z)</code>.
         * @param k3 the integer <code>k3</code> where <code>x<sup>m</sup> +
         * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
         * represents the reduction polynomial <code>f(z)</code>.
         * @param a the coefficient <code>a</code> in the weierstrass equation
         * for non-supersingular elliptic curves over
         * <code>f<sub>2<sup>m</sup></sub></code>.
         * @param b the coefficient <code>b</code> in the weierstrass equation
         * for non-supersingular elliptic curves over
         * <code>f<sub>2<sup>m</sup></sub></code>.
         */
        public f2m(
            int m,
            int k1,
            int k2,
            int k3,
            biginteger a,
            biginteger b)
        {
            this(m, k1, k2, k3, a, b, null, null);
        }

        /**
         * constructor for pentanomial polynomial basis (ppb).
         * @param m  the exponent <code>m</code> of
         * <code>f<sub>2<sup>m</sup></sub></code>.
         * @param k1 the integer <code>k1</code> where <code>x<sup>m</sup> +
         * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
         * represents the reduction polynomial <code>f(z)</code>.
         * @param k2 the integer <code>k2</code> where <code>x<sup>m</sup> +
         * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
         * represents the reduction polynomial <code>f(z)</code>.
         * @param k3 the integer <code>k3</code> where <code>x<sup>m</sup> +
         * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
         * represents the reduction polynomial <code>f(z)</code>.
         * @param a the coefficient <code>a</code> in the weierstrass equation
         * for non-supersingular elliptic curves over
         * <code>f<sub>2<sup>m</sup></sub></code>.
         * @param b the coefficient <code>b</code> in the weierstrass equation
         * for non-supersingular elliptic curves over
         * <code>f<sub>2<sup>m</sup></sub></code>.
         * @param n the order of the main subgroup of the elliptic curve.
         * @param h the cofactor of the elliptic curve, i.e.
         * <code>#e<sub>a</sub>(f<sub>2<sup>m</sup></sub>) = h * n</code>.
         */
        public f2m(
            int m, 
            int k1, 
            int k2, 
            int k3,
            biginteger a, 
            biginteger b,
            biginteger n,
            biginteger h)
        {
            this.m = m;
            this.k1 = k1;
            this.k2 = k2;
            this.k3 = k3;
            this.n = n;
            this.h = h;

            if (k1 == 0)
            {
                throw new illegalargumentexception("k1 must be > 0");
            }

            if (k2 == 0)
            {
                if (k3 != 0)
                {
                    throw new illegalargumentexception("k3 must be 0 if k2 == 0");
                }
            }
            else
            {
                if (k2 <= k1)
                {
                    throw new illegalargumentexception("k2 must be > k1");
                }

                if (k3 <= k2)
                {
                    throw new illegalargumentexception("k3 must be > k2");
                }
            }

            this.a = frombiginteger(a);
            this.b = frombiginteger(b);
            this.infinity = new ecpoint.f2m(this, null, null);
        }

        public int getfieldsize()
        {
            return m;
        }

        public ecfieldelement frombiginteger(biginteger x)
        {
            return new ecfieldelement.f2m(this.m, this.k1, this.k2, this.k3, x);
        }

        public ecpoint createpoint(biginteger x, biginteger y, boolean withcompression)
        {
            return new ecpoint.f2m(this, frombiginteger(x), frombiginteger(y), withcompression);
        }

        public ecpoint getinfinity()
        {
            return infinity;
        }

        /**
         * returns true if this is a koblitz curve (abc curve).
         * @return true if this is a koblitz curve (abc curve), false otherwise
         */
        public boolean iskoblitz()
        {
            return ((n != null) && (h != null) &&
                    ((a.tobiginteger().equals(ecconstants.zero)) ||
                    (a.tobiginteger().equals(ecconstants.one))) &&
                    (b.tobiginteger().equals(ecconstants.one)));
        }

        /**
         * returns the parameter <code>&mu;</code> of the elliptic curve.
         * @return <code>&mu;</code> of the elliptic curve.
         * @throws illegalargumentexception if the given eccurve is not a
         * koblitz curve.
         */
        synchronized byte getmu()
        {
            if (mu == 0)
            {
                mu = tnaf.getmu(this);
            }
            return mu;
        }

        /**
         * @return the auxiliary values <code>s<sub>0</sub></code> and
         * <code>s<sub>1</sub></code> used for partial modular reduction for
         * koblitz curves.
         */
        synchronized biginteger[] getsi()
        {
            if (si == null)
            {
                si = tnaf.getsi(this);
            }
            return si;
        }

        /**
         * decompresses a compressed point p = (xp, yp) (x9.62 s 4.2.2).
         * 
         * @param ytilde
         *            ~yp, an indication bit for the decompression of yp.
         * @param x1
         *            the field element xp.
         * @return the decompressed point.
         */
        protected ecpoint decompresspoint(int ytilde, biginteger x1)
        {
            ecfieldelement xp = frombiginteger(x1);
            ecfieldelement yp = null;
            if (xp.tobiginteger().equals(ecconstants.zero))
            {
                yp = (ecfieldelement.f2m)b;
                for (int i = 0; i < m - 1; i++)
                {
                    yp = yp.square();
                }
            }
            else
            {
                ecfieldelement beta = xp.add(a).add(b.multiply(xp.square().invert()));
                ecfieldelement z = solvequadradicequation(beta);
                if (z == null)
                {
                    throw new illegalargumentexception("invalid point compression");
                }
                int zbit = z.tobiginteger().testbit(0) ? 1 : 0;
                if (zbit != ytilde)
                {
                    z = z.add(frombiginteger(ecconstants.one));
                }
                yp = xp.multiply(z);
            }

            return new ecpoint.f2m(this, xp, yp, true);
        }
        
        /**
         * solves a quadratic equation <code>z<sup>2</sup> + z = beta</code>(x9.62
         * d.1.6) the other solution is <code>z + 1</code>.
         * 
         * @param beta
         *            the value to solve the qradratic equation for.
         * @return the solution for <code>z<sup>2</sup> + z = beta</code> or
         *         <code>null</code> if no solution exists.
         */
        private ecfieldelement solvequadradicequation(ecfieldelement beta)
        {
            ecfieldelement zeroelement = new ecfieldelement.f2m(
                    this.m, this.k1, this.k2, this.k3, ecconstants.zero);

            if (beta.tobiginteger().equals(ecconstants.zero))
            {
                return zeroelement;
            }

            ecfieldelement z = null;
            ecfieldelement gamma = zeroelement;

            random rand = new random();
            do
            {
                ecfieldelement t = new ecfieldelement.f2m(this.m, this.k1,
                        this.k2, this.k3, new biginteger(m, rand));
                z = zeroelement;
                ecfieldelement w = beta;
                for (int i = 1; i <= m - 1; i++)
                {
                    ecfieldelement w2 = w.square();
                    z = z.square().add(w2.multiply(t));
                    w = w2.add(beta);
                }
                if (!w.tobiginteger().equals(ecconstants.zero))
                {
                    return null;
                }
                gamma = z.square().add(z);
            }
            while (gamma.tobiginteger().equals(ecconstants.zero));

            return z;
        }
        
        public boolean equals(
            object anobject)
        {
            if (anobject == this) 
            {
                return true;
            }

            if (!(anobject instanceof eccurve.f2m)) 
            {
                return false;
            }

            eccurve.f2m other = (eccurve.f2m)anobject;
            
            return (this.m == other.m) && (this.k1 == other.k1)
                && (this.k2 == other.k2) && (this.k3 == other.k3)
                && a.equals(other.a) && b.equals(other.b);
        }

        public int hashcode()
        {
            return this.a.hashcode() ^ this.b.hashcode() ^ m ^ k1 ^ k2 ^ k3;
        }

        public int getm()
        {
            return m;
        }

        /**
         * return true if curve uses a trinomial basis.
         * 
         * @return true if curve trinomial, false otherwise.
         */
        public boolean istrinomial()
        {
            return k2 == 0 && k3 == 0;
        }
        
        public int getk1()
        {
            return k1;
        }

        public int getk2()
        {
            return k2;
        }

        public int getk3()
        {
            return k3;
        }

        public biginteger getn()
        {
            return n;
        }

        public biginteger geth()
        {
            return h;
        }
    }
}
