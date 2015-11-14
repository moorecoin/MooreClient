package org.ripple.bouncycastle.pqc.math.linearalgebra;


/**
 * this class implements vectors over the finite field
 * <tt>gf(2<sup>m</sup>)</tt> for small <tt>m</tt> (i.e.,
 * <tt>1&lt;m&lt;32</tt>). it extends the abstract class {@link vector}.
 */
public class gf2mvector
    extends vector
{

    /**
     * the finite field this vector is defined over
     */
    private gf2mfield field;

    /**
     * the element array
     */
    private int[] vector;

    /**
     * creates the vector over gf(2^m) of given length and with elements from
     * array v (beginning at the first bit)
     *
     * @param field finite field
     * @param v     array with elements of vector
     */
    public gf2mvector(gf2mfield field, byte[] v)
    {
        this.field = new gf2mfield(field);

        // decode vector
        int d = 8;
        int count = 1;
        while (field.getdegree() > d)
        {
            count++;
            d += 8;
        }

        if ((v.length % count) != 0)
        {
            throw new illegalargumentexception(
                "byte array is not an encoded vector over the given finite field.");
        }

        length = v.length / count;
        vector = new int[length];
        count = 0;
        for (int i = 0; i < vector.length; i++)
        {
            for (int j = 0; j < d; j += 8)
            {
                vector[i] |= (v[count++] & 0xff) << j;
            }
            if (!field.iselementofthisfield(vector[i]))
            {
                throw new illegalargumentexception(
                    "byte array is not an encoded vector over the given finite field.");
            }
        }
    }

    /**
     * create a new vector over <tt>gf(2<sup>m</sup>)</tt> of the given
     * length and element array.
     *
     * @param field  the finite field <tt>gf(2<sup>m</sup>)</tt>
     * @param vector the element array
     */
    public gf2mvector(gf2mfield field, int[] vector)
    {
        this.field = field;
        length = vector.length;
        for (int i = vector.length - 1; i >= 0; i--)
        {
            if (!field.iselementofthisfield(vector[i]))
            {
                throw new arithmeticexception(
                    "element array is not specified over the given finite field.");
            }
        }
        this.vector = intutils.clone(vector);
    }

    /**
     * copy constructor.
     *
     * @param other another {@link gf2mvector}
     */
    public gf2mvector(gf2mvector other)
    {
        field = new gf2mfield(other.field);
        length = other.length;
        vector = intutils.clone(other.vector);
    }

    /**
     * @return the finite field this vector is defined over
     */
    public gf2mfield getfield()
    {
        return field;
    }

    /**
     * @return int[] form of this vector
     */
    public int[] getintarrayform()
    {
        return intutils.clone(vector);
    }

    /**
     * @return a byte array encoding of this vector
     */
    public byte[] getencoded()
    {
        int d = 8;
        int count = 1;
        while (field.getdegree() > d)
        {
            count++;
            d += 8;
        }

        byte[] res = new byte[vector.length * count];
        count = 0;
        for (int i = 0; i < vector.length; i++)
        {
            for (int j = 0; j < d; j += 8)
            {
                res[count++] = (byte)(vector[i] >>> j);
            }
        }

        return res;
    }

    /**
     * @return whether this is the zero vector (i.e., all elements are zero)
     */
    public boolean iszero()
    {
        for (int i = vector.length - 1; i >= 0; i--)
        {
            if (vector[i] != 0)
            {
                return false;
            }
        }
        return true;
    }

    /**
     * add another vector to this vector. method is not yet implemented.
     *
     * @param addend the other vector
     * @return <tt>this + addend</tt>
     * @throws arithmeticexception if the other vector is not defined over the same field as
     * this vector.
     * <p/>
     * todo: implement this method
     */
    public vector add(vector addend)
    {
        throw new runtimeexception("not implemented");
    }

    /**
     * multiply this vector with a permutation.
     *
     * @param p the permutation
     * @return <tt>this*p = p*this</tt>
     */
    public vector multiply(permutation p)
    {
        int[] pvec = p.getvector();
        if (length != pvec.length)
        {
            throw new arithmeticexception(
                "permutation size and vector size mismatch");
        }

        int[] result = new int[length];
        for (int i = 0; i < pvec.length; i++)
        {
            result[i] = vector[pvec[i]];
        }

        return new gf2mvector(field, result);
    }

    /**
     * compare this vector with another object.
     *
     * @param other the other object
     * @return the result of the comparison
     */
    public boolean equals(object other)
    {

        if (!(other instanceof gf2mvector))
        {
            return false;
        }
        gf2mvector othervec = (gf2mvector)other;

        if (!field.equals(othervec.field))
        {
            return false;
        }

        return intutils.equals(vector, othervec.vector);
    }

    /**
     * @return the hash code of this vector
     */
    public int hashcode()
    {
        int hash = this.field.hashcode();
        hash = hash * 31 + vector.hashcode();
        return hash;
    }

    /**
     * @return a human readable form of this vector
     */
    public string tostring()
    {
        stringbuffer buf = new stringbuffer();
        for (int i = 0; i < vector.length; i++)
        {
            for (int j = 0; j < field.getdegree(); j++)
            {
                int r = j & 0x1f;
                int bitmask = 1 << r;
                int coeff = vector[i] & bitmask;
                if (coeff != 0)
                {
                    buf.append('1');
                }
                else
                {
                    buf.append('0');
                }
            }
            buf.append(' ');
        }
        return buf.tostring();
    }

}
