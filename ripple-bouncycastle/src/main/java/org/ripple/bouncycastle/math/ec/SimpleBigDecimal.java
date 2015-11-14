package org.ripple.bouncycastle.math.ec;

import java.math.biginteger;

/**
 * class representing a simple version of a big decimal. a
 * <code>simplebigdecimal</code> is basically a
 * {@link java.math.biginteger biginteger} with a few digits on the right of
 * the decimal point. the number of (binary) digits on the right of the decimal
 * point is called the <code>scale</code> of the <code>simplebigdecimal</code>.
 * unlike in {@link java.math.bigdecimal bigdecimal}, the scale is not adjusted
 * automatically, but must be set manually. all <code>simplebigdecimal</code>s
 * taking part in the same arithmetic operation must have equal scale. the
 * result of a multiplication of two <code>simplebigdecimal</code>s returns a
 * <code>simplebigdecimal</code> with double scale.
 */
class simplebigdecimal
    //extends number   // not in j2me - add compatibility class?
{
    private static final long serialversionuid = 1l;

    private final biginteger bigint;
    private final int scale;

    /**
     * returns a <code>simplebigdecimal</code> representing the same numerical
     * value as <code>value</code>.
     * @param value the value of the <code>simplebigdecimal</code> to be
     * created. 
     * @param scale the scale of the <code>simplebigdecimal</code> to be
     * created. 
     * @return the such created <code>simplebigdecimal</code>.
     */
    public static simplebigdecimal getinstance(biginteger value, int scale)
    {
        return new simplebigdecimal(value.shiftleft(scale), scale);
    }

    /**
     * constructor for <code>simplebigdecimal</code>. the value of the
     * constructed <code>simplebigdecimal</code> equals <code>bigint / 
     * 2<sup>scale</sup></code>.
     * @param bigint the <code>bigint</code> value parameter.
     * @param scale the scale of the constructed <code>simplebigdecimal</code>.
     */
    public simplebigdecimal(biginteger bigint, int scale)
    {
        if (scale < 0)
        {
            throw new illegalargumentexception("scale may not be negative");
        }

        this.bigint = bigint;
        this.scale = scale;
    }

    private simplebigdecimal(simplebigdecimal limbigdec)
    {
        bigint = limbigdec.bigint;
        scale = limbigdec.scale;
    }

    private void checkscale(simplebigdecimal b)
    {
        if (scale != b.scale)
        {
            throw new illegalargumentexception("only simplebigdecimal of " +
                "same scale allowed in arithmetic operations");
        }
    }

    public simplebigdecimal adjustscale(int newscale)
    {
        if (newscale < 0)
        {
            throw new illegalargumentexception("scale may not be negative");
        }

        if (newscale == scale)
        {
            return new simplebigdecimal(this);
        }

        return new simplebigdecimal(bigint.shiftleft(newscale - scale),
                newscale);
    }

    public simplebigdecimal add(simplebigdecimal b)
    {
        checkscale(b);
        return new simplebigdecimal(bigint.add(b.bigint), scale);
    }

    public simplebigdecimal add(biginteger b)
    {
        return new simplebigdecimal(bigint.add(b.shiftleft(scale)), scale);
    }

    public simplebigdecimal negate()
    {
        return new simplebigdecimal(bigint.negate(), scale);
    }

    public simplebigdecimal subtract(simplebigdecimal b)
    {
        return add(b.negate());
    }

    public simplebigdecimal subtract(biginteger b)
    {
        return new simplebigdecimal(bigint.subtract(b.shiftleft(scale)),
                scale);
    }

    public simplebigdecimal multiply(simplebigdecimal b)
    {
        checkscale(b);
        return new simplebigdecimal(bigint.multiply(b.bigint), scale + scale);
    }

    public simplebigdecimal multiply(biginteger b)
    {
        return new simplebigdecimal(bigint.multiply(b), scale);
    }

    public simplebigdecimal divide(simplebigdecimal b)
    {
        checkscale(b);
        biginteger dividend = bigint.shiftleft(scale);
        return new simplebigdecimal(dividend.divide(b.bigint), scale);
    }

    public simplebigdecimal divide(biginteger b)
    {
        return new simplebigdecimal(bigint.divide(b), scale);
    }

    public simplebigdecimal shiftleft(int n)
    {
        return new simplebigdecimal(bigint.shiftleft(n), scale);
    }

    public int compareto(simplebigdecimal val)
    {
        checkscale(val);
        return bigint.compareto(val.bigint);
    }

    public int compareto(biginteger val)
    {
        return bigint.compareto(val.shiftleft(scale));
    }

    public biginteger floor()
    {
        return bigint.shiftright(scale);
    }

    public biginteger round()
    {
        simplebigdecimal onehalf = new simplebigdecimal(ecconstants.one, 1);
        return add(onehalf.adjustscale(scale)).floor();
    }

    public int intvalue()
    {
        return floor().intvalue();
    }
    
    public long longvalue()
    {
        return floor().longvalue();
    }
          /* non-j2me compliant.
    public double doublevalue()
    {
        return double.valueof(tostring()).doublevalue();
    }

    public float floatvalue()
    {
        return float.valueof(tostring()).floatvalue();
    }
       */
    public int getscale()
    {
        return scale;
    }

    public string tostring()
    {
        if (scale == 0)
        {
            return bigint.tostring();
        }

        biginteger floorbigint = floor();
        
        biginteger fract = bigint.subtract(floorbigint.shiftleft(scale));
        if (bigint.signum() == -1)
        {
            fract = ecconstants.one.shiftleft(scale).subtract(fract);
        }

        if ((floorbigint.signum() == -1) && (!(fract.equals(ecconstants.zero))))
        {
            floorbigint = floorbigint.add(ecconstants.one);
        }
        string leftofpoint = floorbigint.tostring();

        char[] fractchararr = new char[scale];
        string fractstr = fract.tostring(2);
        int fractlen = fractstr.length();
        int zeroes = scale - fractlen;
        for (int i = 0; i < zeroes; i++)
        {
            fractchararr[i] = '0';
        }
        for (int j = 0; j < fractlen; j++)
        {
            fractchararr[zeroes + j] = fractstr.charat(j);
        }
        string rightofpoint = new string(fractchararr);

        stringbuffer sb = new stringbuffer(leftofpoint);
        sb.append(".");
        sb.append(rightofpoint);

        return sb.tostring();
    }

    public boolean equals(object o)
    {
        if (this == o)
        {
            return true;
        }

        if (!(o instanceof simplebigdecimal))
        {
            return false;
        }

        simplebigdecimal other = (simplebigdecimal)o;
        return ((bigint.equals(other.bigint)) && (scale == other.scale));
    }

    public int hashcode()
    {
        return bigint.hashcode() ^ scale;
    }

}
