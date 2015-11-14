package org.ripple.bouncycastle.math.ec;

import java.math.biginteger;

import org.ripple.bouncycastle.asn1.x9.x9integerconverter;

/**
 * base class for points on elliptic curves.
 */
public abstract class ecpoint
{
    eccurve        curve;
    ecfieldelement x;
    ecfieldelement y;

    protected boolean withcompression;

    protected ecmultiplier multiplier = null;

    protected precompinfo precompinfo = null;

    private static x9integerconverter converter = new x9integerconverter();

    protected ecpoint(eccurve curve, ecfieldelement x, ecfieldelement y)
    {
        this.curve = curve;
        this.x = x;
        this.y = y;
    }
    
    public eccurve getcurve()
    {
        return curve;
    }
    
    public ecfieldelement getx()
    {
        return x;
    }

    public ecfieldelement gety()
    {
        return y;
    }

    public boolean isinfinity()
    {
        return x == null && y == null;
    }

    public boolean iscompressed()
    {
        return withcompression;
    }

    public boolean equals(
        object  other)
    {
        if (other == this)
        {
            return true;
        }

        if (!(other instanceof ecpoint))
        {
            return false;
        }

        ecpoint o = (ecpoint)other;

        if (this.isinfinity())
        {
            return o.isinfinity();
        }

        return x.equals(o.x) && y.equals(o.y);
    }

    public int hashcode()
    {
        if (this.isinfinity())
        {
            return 0;
        }
        
        return x.hashcode() ^ y.hashcode();
    }

//    /**
//     * mainly for testing. explicitly set the <code>ecmultiplier</code>.
//     * @param multiplier the <code>ecmultiplier</code> to be used to multiply
//     * this <code>ecpoint</code>.
//     */
//    public void setecmultiplier(ecmultiplier multiplier)
//    {
//        this.multiplier = multiplier;
//    }

    /**
     * sets the <code>precompinfo</code>. used by <code>ecmultiplier</code>s
     * to save the precomputation for this <code>ecpoint</code> to store the
     * precomputation result for use by subsequent multiplication.
     * @param precompinfo the values precomputed by the
     * <code>ecmultiplier</code>.
     */
    void setprecompinfo(precompinfo precompinfo)
    {
        this.precompinfo = precompinfo;
    }

    public byte[] getencoded()
    {
        return getencoded(withcompression);
    }

    public abstract byte[] getencoded(boolean compressed);

    public abstract ecpoint add(ecpoint b);
    public abstract ecpoint subtract(ecpoint b);
    public abstract ecpoint negate();
    public abstract ecpoint twice();

    /**
     * sets the default <code>ecmultiplier</code>, unless already set. 
     */
    synchronized void assertecmultiplier()
    {
        if (this.multiplier == null)
        {
            this.multiplier = new fpnafmultiplier();
        }
    }

    /**
     * multiplies this <code>ecpoint</code> by the given number.
     * @param k the multiplicator.
     * @return <code>k * this</code>.
     */
    public ecpoint multiply(biginteger k)
    {
        if (k.signum() < 0)
        {
            throw new illegalargumentexception("the multiplicator cannot be negative");
        }

        if (this.isinfinity())
        {
            return this;
        }

        if (k.signum() == 0)
        {
            return this.curve.getinfinity();
        }

        assertecmultiplier();
        return this.multiplier.multiply(this, k, precompinfo);
    }

    /**
     * elliptic curve points over fp
     */
    public static class fp extends ecpoint
    {
        
        /**
         * create a point which encodes with point compression.
         * 
         * @param curve the curve to use
         * @param x affine x co-ordinate
         * @param y affine y co-ordinate
         */
        public fp(eccurve curve, ecfieldelement x, ecfieldelement y)
        {
            this(curve, x, y, false);
        }

        /**
         * create a point that encodes with or without point compresion.
         * 
         * @param curve the curve to use
         * @param x affine x co-ordinate
         * @param y affine y co-ordinate
         * @param withcompression if true encode with point compression
         */
        public fp(eccurve curve, ecfieldelement x, ecfieldelement y, boolean withcompression)
        {
            super(curve, x, y);

            if ((x != null && y == null) || (x == null && y != null))
            {
                throw new illegalargumentexception("exactly one of the field elements is null");
            }

            this.withcompression = withcompression;
        }
         
        /**
         * return the field element encoded with point compression. (s 4.3.6)
         */
        public byte[] getencoded(boolean compressed)
        {
            if (this.isinfinity()) 
            {
                return new byte[1];
            }

            int qlength = converter.getbytelength(x);
            
            if (compressed)
            {
                byte    pc;
    
                if (this.gety().tobiginteger().testbit(0))
                {
                    pc = 0x03;
                }
                else
                {
                    pc = 0x02;
                }
    
                byte[]  x = converter.integertobytes(this.getx().tobiginteger(), qlength);
                byte[]  po = new byte[x.length + 1];
    
                po[0] = pc;
                system.arraycopy(x, 0, po, 1, x.length);
    
                return po;
            }
            else
            {
                byte[]  x = converter.integertobytes(this.getx().tobiginteger(), qlength);
                byte[]  y = converter.integertobytes(this.gety().tobiginteger(), qlength);
                byte[]  po = new byte[x.length + y.length + 1];
                
                po[0] = 0x04;
                system.arraycopy(x, 0, po, 1, x.length);
                system.arraycopy(y, 0, po, x.length + 1, y.length);

                return po;
            }
        }

        // b.3 pg 62
        public ecpoint add(ecpoint b)
        {
            if (this.isinfinity())
            {
                return b;
            }

            if (b.isinfinity())
            {
                return this;
            }

            // check if b = this or b = -this
            if (this.x.equals(b.x))
            {
                if (this.y.equals(b.y))
                {
                    // this = b, i.e. this must be doubled
                    return this.twice();
                }

                // this = -b, i.e. the result is the point at infinity
                return this.curve.getinfinity();
            }

            ecfieldelement gamma = b.y.subtract(this.y).divide(b.x.subtract(this.x));

            ecfieldelement x3 = gamma.square().subtract(this.x).subtract(b.x);
            ecfieldelement y3 = gamma.multiply(this.x.subtract(x3)).subtract(this.y);

            return new ecpoint.fp(curve, x3, y3, withcompression);
        }

        // b.3 pg 62
        public ecpoint twice()
        {
            if (this.isinfinity())
            {
                // twice identity element (point at infinity) is identity
                return this;
            }

            if (this.y.tobiginteger().signum() == 0) 
            {
                // if y1 == 0, then (x1, y1) == (x1, -y1)
                // and hence this = -this and thus 2(x1, y1) == infinity
                return this.curve.getinfinity();
            }

            ecfieldelement two = this.curve.frombiginteger(biginteger.valueof(2));
            ecfieldelement three = this.curve.frombiginteger(biginteger.valueof(3));
            ecfieldelement gamma = this.x.square().multiply(three).add(curve.a).divide(y.multiply(two));

            ecfieldelement x3 = gamma.square().subtract(this.x.multiply(two));
            ecfieldelement y3 = gamma.multiply(this.x.subtract(x3)).subtract(this.y);
                
            return new ecpoint.fp(curve, x3, y3, this.withcompression);
        }

        // d.3.2 pg 102 (see note:)
        public ecpoint subtract(ecpoint b)
        {
            if (b.isinfinity())
            {
                return this;
            }

            // add -b
            return add(b.negate());
        }

        public ecpoint negate()
        {
            return new ecpoint.fp(curve, this.x, this.y.negate(), this.withcompression);
        }

        /**
         * sets the default <code>ecmultiplier</code>, unless already set. 
         */
        synchronized void assertecmultiplier()
        {
            if (this.multiplier == null)
            {
                this.multiplier = new wnafmultiplier();
            }
        }
    }

    /**
     * elliptic curve points over f2m
     */
    public static class f2m extends ecpoint
    {
        /**
         * @param curve base curve
         * @param x x point
         * @param y y point
         */
        public f2m(eccurve curve, ecfieldelement x, ecfieldelement y)
        {
            this(curve, x, y, false);
        }
        
        /**
         * @param curve base curve
         * @param x x point
         * @param y y point
         * @param withcompression true if encode with point compression.
         */
        public f2m(eccurve curve, ecfieldelement x, ecfieldelement y, boolean withcompression)
        {
            super(curve, x, y);

            if ((x != null && y == null) || (x == null && y != null))
            {
                throw new illegalargumentexception("exactly one of the field elements is null");
            }
            
            if (x != null)
            {
                // check if x and y are elements of the same field
                ecfieldelement.f2m.checkfieldelements(this.x, this.y);
    
                // check if x and a are elements of the same field
                if (curve != null)
                {
                    ecfieldelement.f2m.checkfieldelements(this.x, this.curve.geta());
                }
            }
            
            this.withcompression = withcompression;
        }

        /* (non-javadoc)
         * @see org.bouncycastle.math.ec.ecpoint#getencoded()
         */
        public byte[] getencoded(boolean compressed)
        {
            if (this.isinfinity()) 
            {
                return new byte[1];
            }

            int bytecount = converter.getbytelength(this.x);
            byte[] x = converter.integertobytes(this.getx().tobiginteger(), bytecount);
            byte[] po;

            if (compressed)
            {
                // see x9.62 4.3.6 and 4.2.2
                po = new byte[bytecount + 1];

                po[0] = 0x02;
                // x9.62 4.2.2 and 4.3.6:
                // if x = 0 then yptilde := 0, else yptilde is the rightmost
                // bit of y * x^(-1)
                // if yptilde = 0, then pc := 02, else pc := 03
                // note: pc === po[0]
                if (!(this.getx().tobiginteger().equals(ecconstants.zero)))
                {
                    if (this.gety().multiply(this.getx().invert())
                            .tobiginteger().testbit(0))
                    {
                        // yptilde = 1, hence pc = 03
                        po[0] = 0x03;
                    }
                }

                system.arraycopy(x, 0, po, 1, bytecount);
            }
            else
            {
                byte[] y = converter.integertobytes(this.gety().tobiginteger(), bytecount);
    
                po = new byte[bytecount + bytecount + 1];
    
                po[0] = 0x04;
                system.arraycopy(x, 0, po, 1, bytecount);
                system.arraycopy(y, 0, po, bytecount + 1, bytecount);    
            }

            return po;
        }

        /**
         * check, if two <code>ecpoint</code>s can be added or subtracted.
         * @param a the first <code>ecpoint</code> to check.
         * @param b the second <code>ecpoint</code> to check.
         * @throws illegalargumentexception if <code>a</code> and <code>b</code>
         * cannot be added.
         */
        private static void checkpoints(ecpoint a, ecpoint b)
        {
            // check, if points are on the same curve
            if (!(a.curve.equals(b.curve)))
            {
                throw new illegalargumentexception("only points on the same "
                        + "curve can be added or subtracted");
            }

//            ecfieldelement.f2m.checkfieldelements(a.x, b.x);
        }

        /* (non-javadoc)
         * @see org.bouncycastle.math.ec.ecpoint#add(org.bouncycastle.math.ec.ecpoint)
         */
        public ecpoint add(ecpoint b)
        {
            checkpoints(this, b);
            return addsimple((ecpoint.f2m)b);
        }

        /**
         * adds another <code>ecpoints.f2m</code> to <code>this</code> without
         * checking if both points are on the same curve. used by multiplication
         * algorithms, because there all points are a multiple of the same point
         * and hence the checks can be omitted.
         * @param b the other <code>ecpoints.f2m</code> to add to
         * <code>this</code>.
         * @return <code>this + b</code>
         */
        public ecpoint.f2m addsimple(ecpoint.f2m b)
        {
            ecpoint.f2m other = b;
            if (this.isinfinity())
            {
                return other;
            }

            if (other.isinfinity())
            {
                return this;
            }

            ecfieldelement.f2m x2 = (ecfieldelement.f2m)other.getx();
            ecfieldelement.f2m y2 = (ecfieldelement.f2m)other.gety();

            // check if other = this or other = -this
            if (this.x.equals(x2))
            {
                if (this.y.equals(y2))
                {
                    // this = other, i.e. this must be doubled
                    return (ecpoint.f2m)this.twice();
                }

                // this = -other, i.e. the result is the point at infinity
                return (ecpoint.f2m)this.curve.getinfinity();
            }

            ecfieldelement.f2m lambda
                = (ecfieldelement.f2m)(this.y.add(y2)).divide(this.x.add(x2));

            ecfieldelement.f2m x3
                = (ecfieldelement.f2m)lambda.square().add(lambda).add(this.x).add(x2).add(this.curve.geta());

            ecfieldelement.f2m y3
                = (ecfieldelement.f2m)lambda.multiply(this.x.add(x3)).add(x3).add(this.y);

            return new ecpoint.f2m(curve, x3, y3, withcompression);
        }

        /* (non-javadoc)
         * @see org.bouncycastle.math.ec.ecpoint#subtract(org.bouncycastle.math.ec.ecpoint)
         */
        public ecpoint subtract(ecpoint b)
        {
            checkpoints(this, b);
            return subtractsimple((ecpoint.f2m)b);
        }

        /**
         * subtracts another <code>ecpoints.f2m</code> from <code>this</code>
         * without checking if both points are on the same curve. used by
         * multiplication algorithms, because there all points are a multiple
         * of the same point and hence the checks can be omitted.
         * @param b the other <code>ecpoints.f2m</code> to subtract from
         * <code>this</code>.
         * @return <code>this - b</code>
         */
        public ecpoint.f2m subtractsimple(ecpoint.f2m b)
        {
            if (b.isinfinity())
            {
                return this;
            }

            // add -b
            return addsimple((ecpoint.f2m)b.negate());
        }

        /* (non-javadoc)
         * @see org.bouncycastle.math.ec.ecpoint#twice()
         */
        public ecpoint twice()
        {
            if (this.isinfinity()) 
            {
                // twice identity element (point at infinity) is identity
                return this;
            }

            if (this.x.tobiginteger().signum() == 0) 
            {
                // if x1 == 0, then (x1, y1) == (x1, x1 + y1)
                // and hence this = -this and thus 2(x1, y1) == infinity
                return this.curve.getinfinity();
            }

            ecfieldelement.f2m lambda
                = (ecfieldelement.f2m)this.x.add(this.y.divide(this.x));

            ecfieldelement.f2m x3
                = (ecfieldelement.f2m)lambda.square().add(lambda).
                    add(this.curve.geta());

            ecfieldelement one = this.curve.frombiginteger(ecconstants.one);
            ecfieldelement.f2m y3
                = (ecfieldelement.f2m)this.x.square().add(
                    x3.multiply(lambda.add(one)));

            return new ecpoint.f2m(this.curve, x3, y3, withcompression);
        }

        public ecpoint negate()
        {
            return new ecpoint.f2m(curve, this.getx(), this.gety().add(this.getx()), withcompression);
        }

        /**
         * sets the appropriate <code>ecmultiplier</code>, unless already set. 
         */
        synchronized void assertecmultiplier()
        {
            if (this.multiplier == null)
            {
                if (((eccurve.f2m)this.curve).iskoblitz())
                {
                    this.multiplier = new wtaunafmultiplier();
                }
                else
                {
                    this.multiplier = new wnafmultiplier();
                }
            }
        }
    }
}
