package org.ripple.bouncycastle.math.ec;

import java.math.biginteger;
import java.util.random;

public abstract class ecfieldelement
    implements ecconstants
{

    public abstract biginteger     tobiginteger();
    public abstract string         getfieldname();
    public abstract int            getfieldsize();
    public abstract ecfieldelement add(ecfieldelement b);
    public abstract ecfieldelement subtract(ecfieldelement b);
    public abstract ecfieldelement multiply(ecfieldelement b);
    public abstract ecfieldelement divide(ecfieldelement b);
    public abstract ecfieldelement negate();
    public abstract ecfieldelement square();
    public abstract ecfieldelement invert();
    public abstract ecfieldelement sqrt();

    public string tostring()
    {
        return this.tobiginteger().tostring(2);
    }

    public static class fp extends ecfieldelement
    {
        biginteger x;

        biginteger q;
        
        public fp(biginteger q, biginteger x)
        {
            this.x = x;
            
            if (x.compareto(q) >= 0)
            {
                throw new illegalargumentexception("x value too large in field element");
            }

            this.q = q;
        }

        public biginteger tobiginteger()
        {
            return x;
        }

        /**
         * return the field name for this field.
         *
         * @return the string "fp".
         */
        public string getfieldname()
        {
            return "fp";
        }

        public int getfieldsize()
        {
            return q.bitlength();
        }

        public biginteger getq()
        {
            return q;
        }
        
        public ecfieldelement add(ecfieldelement b)
        {
            return new fp(q, x.add(b.tobiginteger()).mod(q));
        }

        public ecfieldelement subtract(ecfieldelement b)
        {
            return new fp(q, x.subtract(b.tobiginteger()).mod(q));
        }

        public ecfieldelement multiply(ecfieldelement b)
        {
            return new fp(q, x.multiply(b.tobiginteger()).mod(q));
        }

        public ecfieldelement divide(ecfieldelement b)
        {
            return new fp(q, x.multiply(b.tobiginteger().modinverse(q)).mod(q));
        }

        public ecfieldelement negate()
        {
            return new fp(q, x.negate().mod(q));
        }

        public ecfieldelement square()
        {
            return new fp(q, x.multiply(x).mod(q));
        }

        public ecfieldelement invert()
        {
            return new fp(q, x.modinverse(q));
        }

        // d.1.4 91
        /**
         * return a sqrt root - the routine verifies that the calculation
         * returns the right value - if none exists it returns null.
         */
        public ecfieldelement sqrt()
        {
            if (!q.testbit(0))
            {
                throw new runtimeexception("not done yet");
            }

            // note: even though this class implements ecconstants don't be tempted to
            // remove the explicit declaration, some j2me environments don't cope.
            // p mod 4 == 3
            if (q.testbit(1))
            {
                // z = g^(u+1) + p, p = 4u + 3
                ecfieldelement z = new fp(q, x.modpow(q.shiftright(2).add(ecconstants.one), q));

                return z.square().equals(this) ? z : null;
            }

            // p mod 4 == 1
            biginteger qminusone = q.subtract(ecconstants.one);

            biginteger legendreexponent = qminusone.shiftright(1);
            if (!(x.modpow(legendreexponent, q).equals(ecconstants.one)))
            {
                return null;
            }

            biginteger u = qminusone.shiftright(2);
            biginteger k = u.shiftleft(1).add(ecconstants.one);

            biginteger q = this.x;
            biginteger fourq = q.shiftleft(2).mod(q);

            biginteger u, v;
            random rand = new random();
            do
            {
                biginteger p;
                do
                {
                    p = new biginteger(q.bitlength(), rand);
                }
                while (p.compareto(q) >= 0
                    || !(p.multiply(p).subtract(fourq).modpow(legendreexponent, q).equals(qminusone)));

                biginteger[] result = lucassequence(q, p, q, k);
                u = result[0];
                v = result[1];

                if (v.multiply(v).mod(q).equals(fourq))
                {
                    // integer division by 2, mod q
                    if (v.testbit(0))
                    {
                        v = v.add(q);
                    }

                    v = v.shiftright(1);

                    //assert v.multiply(v).mod(q).equals(x);

                    return new ecfieldelement.fp(q, v);
                }
            }
            while (u.equals(ecconstants.one) || u.equals(qminusone));

            return null;

//            biginteger qminusone = q.subtract(ecconstants.one);
//            biginteger legendreexponent = qminusone.shiftright(1); //divide(ecconstants.two);
//            if (!(x.modpow(legendreexponent, q).equals(ecconstants.one)))
//            {
//                return null;
//            }
//
//            random rand = new random();
//            biginteger fourx = x.shiftleft(2);
//
//            biginteger r;
//            do
//            {
//                r = new biginteger(q.bitlength(), rand);
//            }
//            while (r.compareto(q) >= 0
//                || !(r.multiply(r).subtract(fourx).modpow(legendreexponent, q).equals(qminusone)));
//
//            biginteger n1 = qminusone.shiftright(2); //.divide(ecconstants.four);
//            biginteger n2 = n1.add(ecconstants.one); //q.add(ecconstants.three).divide(ecconstants.four);
//
//            biginteger wone = wone(r, x, q);
//            biginteger wsum = w(n1, wone, q).add(w(n2, wone, q)).mod(q);
//            biginteger twor = r.shiftleft(1); //ecconstants.two.multiply(r);
//
//            biginteger root = twor.modpow(q.subtract(ecconstants.two), q)
//                .multiply(x).mod(q)
//                .multiply(wsum).mod(q);
//
//            return new fp(q, root);
        }

//        private static biginteger w(biginteger n, biginteger wone, biginteger p)
//        {
//            if (n.equals(ecconstants.one))
//            {
//                return wone;
//            }
//            boolean iseven = !n.testbit(0);
//            n = n.shiftright(1);//divide(ecconstants.two);
//            if (iseven)
//            {
//                biginteger w = w(n, wone, p);
//                return w.multiply(w).subtract(ecconstants.two).mod(p);
//            }
//            biginteger w1 = w(n.add(ecconstants.one), wone, p);
//            biginteger w2 = w(n, wone, p);
//            return w1.multiply(w2).subtract(wone).mod(p);
//        }
//
//        private biginteger wone(biginteger r, biginteger x, biginteger p)
//        {
//            return r.multiply(r).multiply(x.modpow(q.subtract(ecconstants.two), q)).subtract(ecconstants.two).mod(p);
//        }

        private static biginteger[] lucassequence(
            biginteger  p,
            biginteger  p,
            biginteger  q,
            biginteger  k)
        {
            int n = k.bitlength();
            int s = k.getlowestsetbit();

            biginteger uh = ecconstants.one;
            biginteger vl = ecconstants.two;
            biginteger vh = p;
            biginteger ql = ecconstants.one;
            biginteger qh = ecconstants.one;

            for (int j = n - 1; j >= s + 1; --j)
            {
                ql = ql.multiply(qh).mod(p);

                if (k.testbit(j))
                {
                    qh = ql.multiply(q).mod(p);
                    uh = uh.multiply(vh).mod(p);
                    vl = vh.multiply(vl).subtract(p.multiply(ql)).mod(p);
                    vh = vh.multiply(vh).subtract(qh.shiftleft(1)).mod(p);
                }
                else
                {
                    qh = ql;
                    uh = uh.multiply(vl).subtract(ql).mod(p);
                    vh = vh.multiply(vl).subtract(p.multiply(ql)).mod(p);
                    vl = vl.multiply(vl).subtract(ql.shiftleft(1)).mod(p);
                }
            }

            ql = ql.multiply(qh).mod(p);
            qh = ql.multiply(q).mod(p);
            uh = uh.multiply(vl).subtract(ql).mod(p);
            vl = vh.multiply(vl).subtract(p.multiply(ql)).mod(p);
            ql = ql.multiply(qh).mod(p);

            for (int j = 1; j <= s; ++j)
            {
                uh = uh.multiply(vl).mod(p);
                vl = vl.multiply(vl).subtract(ql.shiftleft(1)).mod(p);
                ql = ql.multiply(ql).mod(p);
            }

            return new biginteger[]{ uh, vl };
        }
        
        public boolean equals(object other)
        {
            if (other == this)
            {
                return true;
            }

            if (!(other instanceof ecfieldelement.fp))
            {
                return false;
            }
            
            ecfieldelement.fp o = (ecfieldelement.fp)other;
            return q.equals(o.q) && x.equals(o.x);
        }

        public int hashcode()
        {
            return q.hashcode() ^ x.hashcode();
        }
    }

//    /**
//     * class representing the elements of the finite field
//     * <code>f<sub>2<sup>m</sup></sub></code> in polynomial basis (pb)
//     * representation. both trinomial (tpb) and pentanomial (ppb) polynomial
//     * basis representations are supported. gaussian normal basis (gnb)
//     * representation is not supported.
//     */
//    public static class f2m extends ecfieldelement
//    {
//        biginteger x;
//
//        /**
//         * indicates gaussian normal basis representation (gnb). number chosen
//         * according to x9.62. gnb is not implemented at present.
//         */
//        public static final int gnb = 1;
//
//        /**
//         * indicates trinomial basis representation (tpb). number chosen
//         * according to x9.62.
//         */
//        public static final int tpb = 2;
//
//        /**
//         * indicates pentanomial basis representation (ppb). number chosen
//         * according to x9.62.
//         */
//        public static final int ppb = 3;
//
//        /**
//         * tpb or ppb.
//         */
//        private int representation;
//
//        /**
//         * the exponent <code>m</code> of <code>f<sub>2<sup>m</sup></sub></code>.
//         */
//        private int m;
//
//        /**
//         * tpb: the integer <code>k</code> where <code>x<sup>m</sup> +
//         * x<sup>k</sup> + 1</code> represents the reduction polynomial
//         * <code>f(z)</code>.<br>
//         * ppb: the integer <code>k1</code> where <code>x<sup>m</sup> +
//         * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
//         * represents the reduction polynomial <code>f(z)</code>.<br>
//         */
//        private int k1;
//
//        /**
//         * tpb: always set to <code>0</code><br>
//         * ppb: the integer <code>k2</code> where <code>x<sup>m</sup> +
//         * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
//         * represents the reduction polynomial <code>f(z)</code>.<br>
//         */
//        private int k2;
//
//        /**
//         * tpb: always set to <code>0</code><br>
//         * ppb: the integer <code>k3</code> where <code>x<sup>m</sup> +
//         * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
//         * represents the reduction polynomial <code>f(z)</code>.<br>
//         */
//        private int k3;
//        
//        /**
//         * constructor for ppb.
//         * @param m  the exponent <code>m</code> of
//         * <code>f<sub>2<sup>m</sup></sub></code>.
//         * @param k1 the integer <code>k1</code> where <code>x<sup>m</sup> +
//         * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
//         * represents the reduction polynomial <code>f(z)</code>.
//         * @param k2 the integer <code>k2</code> where <code>x<sup>m</sup> +
//         * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
//         * represents the reduction polynomial <code>f(z)</code>.
//         * @param k3 the integer <code>k3</code> where <code>x<sup>m</sup> +
//         * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
//         * represents the reduction polynomial <code>f(z)</code>.
//         * @param x the biginteger representing the value of the field element.
//         */
//        public f2m(
//            int m, 
//            int k1, 
//            int k2, 
//            int k3,
//            biginteger x)
//        {
////            super(x);
//            this.x = x;
//
//            if ((k2 == 0) && (k3 == 0))
//            {
//                this.representation = tpb;
//            }
//            else
//            {
//                if (k2 >= k3)
//                {
//                    throw new illegalargumentexception(
//                            "k2 must be smaller than k3");
//                }
//                if (k2 <= 0)
//                {
//                    throw new illegalargumentexception(
//                            "k2 must be larger than 0");
//                }
//                this.representation = ppb;
//            }
//
//            if (x.signum() < 0)
//            {
//                throw new illegalargumentexception("x value cannot be negative");
//            }
//
//            this.m = m;
//            this.k1 = k1;
//            this.k2 = k2;
//            this.k3 = k3;
//        }
//
//        /**
//         * constructor for tpb.
//         * @param m  the exponent <code>m</code> of
//         * <code>f<sub>2<sup>m</sup></sub></code>.
//         * @param k the integer <code>k</code> where <code>x<sup>m</sup> +
//         * x<sup>k</sup> + 1</code> represents the reduction
//         * polynomial <code>f(z)</code>.
//         * @param x the biginteger representing the value of the field element.
//         */
//        public f2m(int m, int k, biginteger x)
//        {
//            // set k1 to k, and set k2 and k3 to 0
//            this(m, k, 0, 0, x);
//        }
//
//        public biginteger tobiginteger()
//        {
//            return x;
//        }
//
//        public string getfieldname()
//        {
//            return "f2m";
//        }
//
//        public int getfieldsize()
//        {
//            return m;
//        }
//
//        /**
//         * checks, if the ecfieldelements <code>a</code> and <code>b</code>
//         * are elements of the same field <code>f<sub>2<sup>m</sup></sub></code>
//         * (having the same representation).
//         * @param a field element.
//         * @param b field element to be compared.
//         * @throws illegalargumentexception if <code>a</code> and <code>b</code>
//         * are not elements of the same field
//         * <code>f<sub>2<sup>m</sup></sub></code> (having the same
//         * representation). 
//         */
//        public static void checkfieldelements(
//            ecfieldelement a,
//            ecfieldelement b)
//        {
//            if ((!(a instanceof f2m)) || (!(b instanceof f2m)))
//            {
//                throw new illegalargumentexception("field elements are not "
//                        + "both instances of ecfieldelement.f2m");
//            }
//
//            if ((a.tobiginteger().signum() < 0) || (b.tobiginteger().signum() < 0))
//            {
//                throw new illegalargumentexception(
//                        "x value may not be negative");
//            }
//
//            ecfieldelement.f2m af2m = (ecfieldelement.f2m)a;
//            ecfieldelement.f2m bf2m = (ecfieldelement.f2m)b;
//
//            if ((af2m.m != bf2m.m) || (af2m.k1 != bf2m.k1)
//                    || (af2m.k2 != bf2m.k2) || (af2m.k3 != bf2m.k3))
//            {
//                throw new illegalargumentexception("field elements are not "
//                        + "elements of the same field f2m");
//            }
//
//            if (af2m.representation != bf2m.representation)
//            {
//                // should never occur
//                throw new illegalargumentexception(
//                        "one of the field "
//                                + "elements are not elements has incorrect representation");
//            }
//        }
//
//        /**
//         * computes <code>z * a(z) mod f(z)</code>, where <code>f(z)</code> is
//         * the reduction polynomial of <code>this</code>.
//         * @param a the polynomial <code>a(z)</code> to be multiplied by
//         * <code>z mod f(z)</code>.
//         * @return <code>z * a(z) mod f(z)</code>
//         */
//        private biginteger multzmodf(final biginteger a)
//        {
//            // left-shift of a(z)
//            biginteger az = a.shiftleft(1);
//            if (az.testbit(this.m)) 
//            {
//                // if the coefficient of z^m in a(z) equals 1, reduction
//                // modulo f(z) is performed: add f(z) to to a(z):
//                // step 1: unset mth coeffient of a(z)
//                az = az.clearbit(this.m);
//
//                // step 2: add r(z) to a(z), where r(z) is defined as
//                // f(z) = z^m + r(z), and k1, k2, k3 are the positions of
//                // the non-zero coefficients in r(z)
//                az = az.flipbit(0);
//                az = az.flipbit(this.k1);
//                if (this.representation == ppb) 
//                {
//                    az = az.flipbit(this.k2);
//                    az = az.flipbit(this.k3);
//                }
//            }
//            return az;
//        }
//
//        public ecfieldelement add(final ecfieldelement b)
//        {
//            // no check performed here for performance reasons. instead the
//            // elements involved are checked in ecpoint.f2m
//            // checkfieldelements(this, b);
//            if (b.tobiginteger().signum() == 0)
//            {
//                return this;
//            }
//
//            return new f2m(this.m, this.k1, this.k2, this.k3, this.x.xor(b.tobiginteger()));
//        }
//
//        public ecfieldelement subtract(final ecfieldelement b)
//        {
//            // addition and subtraction are the same in f2m
//            return add(b);
//        }
//
//
//        public ecfieldelement multiply(final ecfieldelement b)
//        {
//            // left-to-right shift-and-add field multiplication in f2m
//            // input: binary polynomials a(z) and b(z) of degree at most m-1
//            // output: c(z) = a(z) * b(z) mod f(z)
//
//            // no check performed here for performance reasons. instead the
//            // elements involved are checked in ecpoint.f2m
//            // checkfieldelements(this, b);
//            final biginteger az = this.x;
//            biginteger bz = b.tobiginteger();
//            biginteger cz;
//
//            // compute c(z) = a(z) * b(z) mod f(z)
//            if (az.testbit(0)) 
//            {
//                cz = bz;
//            } 
//            else 
//            {
//                cz = ecconstants.zero;
//            }
//
//            for (int i = 1; i < this.m; i++) 
//            {
//                // b(z) := z * b(z) mod f(z)
//                bz = multzmodf(bz);
//
//                if (az.testbit(i)) 
//                {
//                    // if the coefficient of x^i in a(z) equals 1, b(z) is added
//                    // to c(z)
//                    cz = cz.xor(bz);
//                }
//            }
//            return new ecfieldelement.f2m(m, this.k1, this.k2, this.k3, cz);
//        }
//
//
//        public ecfieldelement divide(final ecfieldelement b)
//        {
//            // there may be more efficient implementations
//            ecfieldelement binv = b.invert();
//            return multiply(binv);
//        }
//
//        public ecfieldelement negate()
//        {
//            // -x == x holds for all x in f2m
//            return this;
//        }
//
//        public ecfieldelement square()
//        {
//            // naive implementation, can probably be speeded up using modular
//            // reduction
//            return multiply(this);
//        }
//
//        public ecfieldelement invert()
//        {
//            // inversion in f2m using the extended euclidean algorithm
//            // input: a nonzero polynomial a(z) of degree at most m-1
//            // output: a(z)^(-1) mod f(z)
//
//            // u(z) := a(z)
//            biginteger uz = this.x;
//            if (uz.signum() <= 0) 
//            {
//                throw new arithmeticexception("x is zero or negative, " +
//                        "inversion is impossible");
//            }
//
//            // v(z) := f(z)
//            biginteger vz = ecconstants.zero.setbit(m);
//            vz = vz.setbit(0);
//            vz = vz.setbit(this.k1);
//            if (this.representation == ppb) 
//            {
//                vz = vz.setbit(this.k2);
//                vz = vz.setbit(this.k3);
//            }
//
//            // g1(z) := 1, g2(z) := 0
//            biginteger g1z = ecconstants.one;
//            biginteger g2z = ecconstants.zero;
//
//            // while u != 1
//            while (!(uz.equals(ecconstants.zero))) 
//            {
//                // j := deg(u(z)) - deg(v(z))
//                int j = uz.bitlength() - vz.bitlength();
//
//                // if j < 0 then: u(z) <-> v(z), g1(z) <-> g2(z), j := -j
//                if (j < 0) 
//                {
//                    final biginteger uzcopy = uz;
//                    uz = vz;
//                    vz = uzcopy;
//
//                    final biginteger g1zcopy = g1z;
//                    g1z = g2z;
//                    g2z = g1zcopy;
//
//                    j = -j;
//                }
//
//                // u(z) := u(z) + z^j * v(z)
//                // note, that no reduction modulo f(z) is required, because
//                // deg(u(z) + z^j * v(z)) <= max(deg(u(z)), j + deg(v(z)))
//                // = max(deg(u(z)), deg(u(z)) - deg(v(z)) + deg(v(z))
//                // = deg(u(z))
//                uz = uz.xor(vz.shiftleft(j));
//
//                // g1(z) := g1(z) + z^j * g2(z)
//                g1z = g1z.xor(g2z.shiftleft(j));
////                if (g1z.bitlength() > this.m) {
////                    throw new arithmeticexception(
////                            "deg(g1z) >= m, g1z = " + g1z.tostring(2));
////                }
//            }
//            return new ecfieldelement.f2m(
//                    this.m, this.k1, this.k2, this.k3, g2z);
//        }
//
//        public ecfieldelement sqrt()
//        {
//            throw new runtimeexception("not implemented");
//        }
//
//        /**
//         * @return the representation of the field
//         * <code>f<sub>2<sup>m</sup></sub></code>, either of
//         * tpb (trinomial
//         * basis representation) or
//         * ppb (pentanomial
//         * basis representation).
//         */
//        public int getrepresentation()
//        {
//            return this.representation;
//        }
//
//        /**
//         * @return the degree <code>m</code> of the reduction polynomial
//         * <code>f(z)</code>.
//         */
//        public int getm()
//        {
//            return this.m;
//        }
//
//        /**
//         * @return tpb: the integer <code>k</code> where <code>x<sup>m</sup> +
//         * x<sup>k</sup> + 1</code> represents the reduction polynomial
//         * <code>f(z)</code>.<br>
//         * ppb: the integer <code>k1</code> where <code>x<sup>m</sup> +
//         * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
//         * represents the reduction polynomial <code>f(z)</code>.<br>
//         */
//        public int getk1()
//        {
//            return this.k1;
//        }
//
//        /**
//         * @return tpb: always returns <code>0</code><br>
//         * ppb: the integer <code>k2</code> where <code>x<sup>m</sup> +
//         * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
//         * represents the reduction polynomial <code>f(z)</code>.<br>
//         */
//        public int getk2()
//        {
//            return this.k2;
//        }
//
//        /**
//         * @return tpb: always set to <code>0</code><br>
//         * ppb: the integer <code>k3</code> where <code>x<sup>m</sup> +
//         * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
//         * represents the reduction polynomial <code>f(z)</code>.<br>
//         */
//        public int getk3()
//        {
//            return this.k3;
//        }
//
//        public boolean equals(object anobject)
//        {
//            if (anobject == this) 
//            {
//                return true;
//            }
//
//            if (!(anobject instanceof ecfieldelement.f2m)) 
//            {
//                return false;
//            }
//
//            ecfieldelement.f2m b = (ecfieldelement.f2m)anobject;
//            
//            return ((this.m == b.m) && (this.k1 == b.k1) && (this.k2 == b.k2)
//                && (this.k3 == b.k3)
//                && (this.representation == b.representation)
//                && (this.x.equals(b.x)));
//        }
//
//        public int hashcode()
//        {
//            return x.hashcode() ^ m ^ k1 ^ k2 ^ k3;
//        }
//    }

    /**
     * class representing the elements of the finite field
     * <code>f<sub>2<sup>m</sup></sub></code> in polynomial basis (pb)
     * representation. both trinomial (tpb) and pentanomial (ppb) polynomial
     * basis representations are supported. gaussian normal basis (gnb)
     * representation is not supported.
     */
    public static class f2m extends ecfieldelement
    {
        /**
         * indicates gaussian normal basis representation (gnb). number chosen
         * according to x9.62. gnb is not implemented at present.
         */
        public static final int gnb = 1;

        /**
         * indicates trinomial basis representation (tpb). number chosen
         * according to x9.62.
         */
        public static final int tpb = 2;

        /**
         * indicates pentanomial basis representation (ppb). number chosen
         * according to x9.62.
         */
        public static final int ppb = 3;

        /**
         * tpb or ppb.
         */
        private int representation;

        /**
         * the exponent <code>m</code> of <code>f<sub>2<sup>m</sup></sub></code>.
         */
        private int m;

        /**
         * tpb: the integer <code>k</code> where <code>x<sup>m</sup> +
         * x<sup>k</sup> + 1</code> represents the reduction polynomial
         * <code>f(z)</code>.<br>
         * ppb: the integer <code>k1</code> where <code>x<sup>m</sup> +
         * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
         * represents the reduction polynomial <code>f(z)</code>.<br>
         */
        private int k1;

        /**
         * tpb: always set to <code>0</code><br>
         * ppb: the integer <code>k2</code> where <code>x<sup>m</sup> +
         * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
         * represents the reduction polynomial <code>f(z)</code>.<br>
         */
        private int k2;

        /**
         * tpb: always set to <code>0</code><br>
         * ppb: the integer <code>k3</code> where <code>x<sup>m</sup> +
         * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
         * represents the reduction polynomial <code>f(z)</code>.<br>
         */
        private int k3;

        /**
         * the <code>intarray</code> holding the bits.
         */
        private intarray x;

        /**
         * the number of <code>int</code>s required to hold <code>m</code> bits.
         */
        private int t;

        /**
         * constructor for ppb.
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
         * @param x the biginteger representing the value of the field element.
         */
        public f2m(
            int m, 
            int k1, 
            int k2, 
            int k3,
            biginteger x)
        {
            // t = m / 32 rounded up to the next integer
            t = (m + 31) >> 5;
            this.x = new intarray(x, t);

            if ((k2 == 0) && (k3 == 0))
            {
                this.representation = tpb;
            }
            else
            {
                if (k2 >= k3)
                {
                    throw new illegalargumentexception(
                            "k2 must be smaller than k3");
                }
                if (k2 <= 0)
                {
                    throw new illegalargumentexception(
                            "k2 must be larger than 0");
                }
                this.representation = ppb;
            }

            if (x.signum() < 0)
            {
                throw new illegalargumentexception("x value cannot be negative");
            }

            this.m = m;
            this.k1 = k1;
            this.k2 = k2;
            this.k3 = k3;
        }

        /**
         * constructor for tpb.
         * @param m  the exponent <code>m</code> of
         * <code>f<sub>2<sup>m</sup></sub></code>.
         * @param k the integer <code>k</code> where <code>x<sup>m</sup> +
         * x<sup>k</sup> + 1</code> represents the reduction
         * polynomial <code>f(z)</code>.
         * @param x the biginteger representing the value of the field element.
         */
        public f2m(int m, int k, biginteger x)
        {
            // set k1 to k, and set k2 and k3 to 0
            this(m, k, 0, 0, x);
        }

        private f2m(int m, int k1, int k2, int k3, intarray x)
        {
            t = (m + 31) >> 5;
            this.x = x;
            this.m = m;
            this.k1 = k1;
            this.k2 = k2;
            this.k3 = k3;

            if ((k2 == 0) && (k3 == 0))
            {
                this.representation = tpb;
            }
            else
            {
                this.representation = ppb;
            }

        }

        public biginteger tobiginteger()
        {
            return x.tobiginteger();
        }

        public string getfieldname()
        {
            return "f2m";
        }

        public int getfieldsize()
        {
            return m;
        }

        /**
         * checks, if the ecfieldelements <code>a</code> and <code>b</code>
         * are elements of the same field <code>f<sub>2<sup>m</sup></sub></code>
         * (having the same representation).
         * @param a field element.
         * @param b field element to be compared.
         * @throws illegalargumentexception if <code>a</code> and <code>b</code>
         * are not elements of the same field
         * <code>f<sub>2<sup>m</sup></sub></code> (having the same
         * representation). 
         */
        public static void checkfieldelements(
            ecfieldelement a,
            ecfieldelement b)
        {
            if ((!(a instanceof f2m)) || (!(b instanceof f2m)))
            {
                throw new illegalargumentexception("field elements are not "
                        + "both instances of ecfieldelement.f2m");
            }

            ecfieldelement.f2m af2m = (ecfieldelement.f2m)a;
            ecfieldelement.f2m bf2m = (ecfieldelement.f2m)b;

            if ((af2m.m != bf2m.m) || (af2m.k1 != bf2m.k1)
                    || (af2m.k2 != bf2m.k2) || (af2m.k3 != bf2m.k3))
            {
                throw new illegalargumentexception("field elements are not "
                        + "elements of the same field f2m");
            }

            if (af2m.representation != bf2m.representation)
            {
                // should never occur
                throw new illegalargumentexception(
                        "one of the field "
                                + "elements are not elements has incorrect representation");
            }
        }

        public ecfieldelement add(final ecfieldelement b)
        {
            // no check performed here for performance reasons. instead the
            // elements involved are checked in ecpoint.f2m
            // checkfieldelements(this, b);
            intarray iarrclone = (intarray)this.x.clone();
            f2m bf2m = (f2m)b;
            iarrclone.addshifted(bf2m.x, 0);
            return new f2m(m, k1, k2, k3, iarrclone);
        }

        public ecfieldelement subtract(final ecfieldelement b)
        {
            // addition and subtraction are the same in f2m
            return add(b);
        }

        public ecfieldelement multiply(final ecfieldelement b)
        {
            // right-to-left comb multiplication in the intarray
            // input: binary polynomials a(z) and b(z) of degree at most m-1
            // output: c(z) = a(z) * b(z) mod f(z)

            // no check performed here for performance reasons. instead the
            // elements involved are checked in ecpoint.f2m
            // checkfieldelements(this, b);
            f2m bf2m = (f2m)b;
            intarray mult = x.multiply(bf2m.x, m);
            mult.reduce(m, new int[]{k1, k2, k3});
            return new f2m(m, k1, k2, k3, mult);
        }

        public ecfieldelement divide(final ecfieldelement b)
        {
            // there may be more efficient implementations
            ecfieldelement binv = b.invert();
            return multiply(binv);
        }

        public ecfieldelement negate()
        {
            // -x == x holds for all x in f2m
            return this;
        }

        public ecfieldelement square()
        {
            intarray squared = x.square(m);
            squared.reduce(m, new int[]{k1, k2, k3});
            return new f2m(m, k1, k2, k3, squared);
        }


        public ecfieldelement invert()
        {
            // inversion in f2m using the extended euclidean algorithm
            // input: a nonzero polynomial a(z) of degree at most m-1
            // output: a(z)^(-1) mod f(z)

            // u(z) := a(z)
            intarray uz = (intarray)this.x.clone();

            // v(z) := f(z)
            intarray vz = new intarray(t);
            vz.setbit(m);
            vz.setbit(0);
            vz.setbit(this.k1);
            if (this.representation == ppb) 
            {
                vz.setbit(this.k2);
                vz.setbit(this.k3);
            }

            // g1(z) := 1, g2(z) := 0
            intarray g1z = new intarray(t);
            g1z.setbit(0);
            intarray g2z = new intarray(t);

            // while u != 0
            while (!uz.iszero())
//            while (uz.getusedlength() > 0)
//            while (uz.bitlength() > 1)
            {
                // j := deg(u(z)) - deg(v(z))
                int j = uz.bitlength() - vz.bitlength();

                // if j < 0 then: u(z) <-> v(z), g1(z) <-> g2(z), j := -j
                if (j < 0) 
                {
                    final intarray uzcopy = uz;
                    uz = vz;
                    vz = uzcopy;

                    final intarray g1zcopy = g1z;
                    g1z = g2z;
                    g2z = g1zcopy;

                    j = -j;
                }

                // u(z) := u(z) + z^j * v(z)
                // note, that no reduction modulo f(z) is required, because
                // deg(u(z) + z^j * v(z)) <= max(deg(u(z)), j + deg(v(z)))
                // = max(deg(u(z)), deg(u(z)) - deg(v(z)) + deg(v(z))
                // = deg(u(z))
                // uz = uz.xor(vz.shiftleft(j));
                // jint = n / 32
                int jint = j >> 5;
                // jint = n % 32
                int jbit = j & 0x1f;
                intarray vzshift = vz.shiftleft(jbit);
                uz.addshifted(vzshift, jint);

                // g1(z) := g1(z) + z^j * g2(z)
//                g1z = g1z.xor(g2z.shiftleft(j));
                intarray g2zshift = g2z.shiftleft(jbit);
                g1z.addshifted(g2zshift, jint);
                
            }
            return new ecfieldelement.f2m(
                    this.m, this.k1, this.k2, this.k3, g2z);
        }

        public ecfieldelement sqrt()
        {
            throw new runtimeexception("not implemented");
        }

        /**
         * @return the representation of the field
         * <code>f<sub>2<sup>m</sup></sub></code>, either of
         * tpb (trinomial
         * basis representation) or
         * ppb (pentanomial
         * basis representation).
         */
        public int getrepresentation()
        {
            return this.representation;
        }

        /**
         * @return the degree <code>m</code> of the reduction polynomial
         * <code>f(z)</code>.
         */
        public int getm()
        {
            return this.m;
        }

        /**
         * @return tpb: the integer <code>k</code> where <code>x<sup>m</sup> +
         * x<sup>k</sup> + 1</code> represents the reduction polynomial
         * <code>f(z)</code>.<br>
         * ppb: the integer <code>k1</code> where <code>x<sup>m</sup> +
         * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
         * represents the reduction polynomial <code>f(z)</code>.<br>
         */
        public int getk1()
        {
            return this.k1;
        }

        /**
         * @return tpb: always returns <code>0</code><br>
         * ppb: the integer <code>k2</code> where <code>x<sup>m</sup> +
         * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
         * represents the reduction polynomial <code>f(z)</code>.<br>
         */
        public int getk2()
        {
            return this.k2;
        }

        /**
         * @return tpb: always set to <code>0</code><br>
         * ppb: the integer <code>k3</code> where <code>x<sup>m</sup> +
         * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
         * represents the reduction polynomial <code>f(z)</code>.<br>
         */
        public int getk3()
        {
            return this.k3;
        }

        public boolean equals(object anobject)
        {
            if (anobject == this) 
            {
                return true;
            }

            if (!(anobject instanceof ecfieldelement.f2m)) 
            {
                return false;
            }

            ecfieldelement.f2m b = (ecfieldelement.f2m)anobject;
            
            return ((this.m == b.m) && (this.k1 == b.k1) && (this.k2 == b.k2)
                && (this.k3 == b.k3)
                && (this.representation == b.representation)
                && (this.x.equals(b.x)));
        }

        public int hashcode()
        {
            return x.hashcode() ^ m ^ k1 ^ k2 ^ k3;
        }
    }
}
