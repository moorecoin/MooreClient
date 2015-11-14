package org.ripple.bouncycastle.pqc.math.linearalgebra;

import java.security.securerandom;

/**
 * this class implements the abstract class <tt>vector</tt> for the case of
 * vectors over the finite field gf(2). <br>
 * for the vector representation the array of type int[] is used, thus one
 * element of the array holds 32 elements of the vector.
 *
 * @see vector
 */
public class gf2vector
    extends vector
{

    /**
     * holds the elements of this vector
     */
    private int[] v;

    /**
     * construct the zero vector of the given length.
     *
     * @param length the length of the vector
     */
    public gf2vector(int length)
    {
        if (length < 0)
        {
            throw new arithmeticexception("negative length.");
        }
        this.length = length;
        v = new int[(length + 31) >> 5];
    }

    /**
     * construct a random gf2vector of the given length.
     *
     * @param length the length of the vector
     * @param sr     the source of randomness
     */
    public gf2vector(int length, securerandom sr)
    {
        this.length = length;

        int size = (length + 31) >> 5;
        v = new int[size];

        // generate random elements
        for (int i = size - 1; i >= 0; i--)
        {
            v[i] = sr.nextint();
        }

        // erase unused bits
        int r = length & 0x1f;
        if (r != 0)
        {
            // erase unused bits
            v[size - 1] &= (1 << r) - 1;
        }
    }

    /**
     * construct a random gf2vector of the given length with the specified
     * number of non-zero coefficients.
     *
     * @param length the length of the vector
     * @param t      the number of non-zero coefficients
     * @param sr     the source of randomness
     */
    public gf2vector(int length, int t, securerandom sr)
    {
        if (t > length)
        {
            throw new arithmeticexception(
                "the hamming weight is greater than the length of vector.");
        }
        this.length = length;

        int size = (length + 31) >> 5;
        v = new int[size];

        int[] help = new int[length];
        for (int i = 0; i < length; i++)
        {
            help[i] = i;
        }

        int m = length;
        for (int i = 0; i < t; i++)
        {
            int j = randutils.nextint(sr, m);
            setbit(help[j]);
            m--;
            help[j] = help[m];
        }
    }

    /**
     * construct a gf2vector of the given length and with elements from the
     * given array. the array is copied and unused bits are masked out.
     *
     * @param length the length of the vector
     * @param v      the element array
     */
    public gf2vector(int length, int[] v)
    {
        if (length < 0)
        {
            throw new arithmeticexception("negative length");
        }
        this.length = length;

        int size = (length + 31) >> 5;

        if (v.length != size)
        {
            throw new arithmeticexception("length mismatch");
        }

        this.v = intutils.clone(v);

        int r = length & 0x1f;
        if (r != 0)
        {
            // erase unused bits
            this.v[size - 1] &= (1 << r) - 1;
        }
    }

    /**
     * copy constructor.
     *
     * @param other another {@link gf2vector}
     */
    public gf2vector(gf2vector other)
    {
        this.length = other.length;
        this.v = intutils.clone(other.v);
    }

    /**
     * construct a new {@link gf2vector} of the given length and with the given
     * element array. the array is not changed and only a reference to the array
     * is stored. no length checking is performed either.
     *
     * @param v      the element array
     * @param length the length of the vector
     */
    protected gf2vector(int[] v, int length)
    {
        this.v = v;
        this.length = length;
    }

    /**
     * construct a new gf2vector with the given length out of the encoded
     * vector.
     *
     * @param length the length of the vector
     * @param encvec the encoded vector
     * @return the decoded vector
     */
    public static gf2vector os2vp(int length, byte[] encvec)
    {
        if (length < 0)
        {
            throw new arithmeticexception("negative length");
        }

        int bytelen = (length + 7) >> 3;

        if (encvec.length > bytelen)
        {
            throw new arithmeticexception("length mismatch");
        }

        return new gf2vector(length, littleendianconversions.tointarray(encvec));
    }

    /**
     * encode this vector as byte array.
     *
     * @return the encoded vector
     */
    public byte[] getencoded()
    {
        int bytelen = (length + 7) >> 3;
        return littleendianconversions.tobytearray(v, bytelen);
    }

    /**
     * @return the int array representation of this vector
     */
    public int[] getvecarray()
    {
        return v;
    }

    /**
     * return the hamming weight of this vector, i.e., compute the number of
     * units of this vector.
     *
     * @return the hamming weight of this vector
     */
    public int gethammingweight()
    {
        int weight = 0;
        for (int i = 0; i < v.length; i++)
        {
            int e = v[i];
            for (int j = 0; j < 32; j++)
            {
                int b = e & 1;
                if (b != 0)
                {
                    weight++;
                }
                e >>>= 1;
            }
        }
        return weight;
    }

    /**
     * @return whether this is the zero vector (i.e., all elements are zero)
     */
    public boolean iszero()
    {
        for (int i = v.length - 1; i >= 0; i--)
        {
            if (v[i] != 0)
            {
                return false;
            }
        }
        return true;
    }

    /**
     * return the value of the bit of this vector at the specified index.
     *
     * @param index the index
     * @return the value of the bit (0 or 1)
     */
    public int getbit(int index)
    {
        if (index >= length)
        {
            throw new indexoutofboundsexception();
        }
        int q = index >> 5;
        int r = index & 0x1f;
        return (v[q] & (1 << r)) >>> r;
    }

    /**
     * set the coefficient at the given index to 1. if the index is out of
     * bounds, do nothing.
     *
     * @param index the index of the coefficient to set
     */
    public void setbit(int index)
    {
        if (index >= length)
        {
            throw new indexoutofboundsexception();
        }
        v[index >> 5] |= 1 << (index & 0x1f);
    }

    /**
     * adds another gf2vector to this vector.
     *
     * @param other another gf2vector
     * @return <tt>this + other</tt>
     * @throws arithmeticexception if the other vector is not a gf2vector or has another
     * length.
     */
    public vector add(vector other)
    {
        if (!(other instanceof gf2vector))
        {
            throw new arithmeticexception("vector is not defined over gf(2)");
        }

        gf2vector othervec = (gf2vector)other;
        if (length != othervec.length)
        {
            throw new arithmeticexception("length mismatch");
        }

        int[] vec = intutils.clone(((gf2vector)other).v);

        for (int i = vec.length - 1; i >= 0; i--)
        {
            vec[i] ^= v[i];
        }

        return new gf2vector(length, vec);
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
            throw new arithmeticexception("length mismatch");
        }

        gf2vector result = new gf2vector(length);

        for (int i = 0; i < pvec.length; i++)
        {
            int e = v[pvec[i] >> 5] & (1 << (pvec[i] & 0x1f));
            if (e != 0)
            {
                result.v[i >> 5] |= 1 << (i & 0x1f);
            }
        }

        return result;
    }

    /**
     * return a new vector consisting of the elements of this vector with the
     * indices given by the set <tt>setj</tt>.
     *
     * @param setj the set of indices of elements to extract
     * @return the new {@link gf2vector}
     *         <tt>[this_setj[0], this_setj[1], ..., this_setj[#setj-1]]</tt>
     */
    public gf2vector extractvector(int[] setj)
    {
        int k = setj.length;
        if (setj[k - 1] > length)
        {
            throw new arithmeticexception("invalid index set");
        }

        gf2vector result = new gf2vector(k);

        for (int i = 0; i < k; i++)
        {
            int e = v[setj[i] >> 5] & (1 << (setj[i] & 0x1f));
            if (e != 0)
            {
                result.v[i >> 5] |= 1 << (i & 0x1f);
            }
        }

        return result;
    }

    /**
     * return a new vector consisting of the first <tt>k</tt> elements of this
     * vector.
     *
     * @param k the number of elements to extract
     * @return a new {@link gf2vector} consisting of the first <tt>k</tt>
     *         elements of this vector
     */
    public gf2vector extractleftvector(int k)
    {
        if (k > length)
        {
            throw new arithmeticexception("invalid length");
        }

        if (k == length)
        {
            return new gf2vector(this);
        }

        gf2vector result = new gf2vector(k);

        int q = k >> 5;
        int r = k & 0x1f;

        system.arraycopy(v, 0, result.v, 0, q);
        if (r != 0)
        {
            result.v[q] = v[q] & ((1 << r) - 1);
        }

        return result;
    }

    /**
     * return a new vector consisting of the last <tt>k</tt> elements of this
     * vector.
     *
     * @param k the number of elements to extract
     * @return a new {@link gf2vector} consisting of the last <tt>k</tt>
     *         elements of this vector
     */
    public gf2vector extractrightvector(int k)
    {
        if (k > length)
        {
            throw new arithmeticexception("invalid length");
        }

        if (k == length)
        {
            return new gf2vector(this);
        }

        gf2vector result = new gf2vector(k);

        int q = (length - k) >> 5;
        int r = (length - k) & 0x1f;
        int length = (k + 31) >> 5;

        int ind = q;
        // if words have to be shifted
        if (r != 0)
        {
            // process all but last word
            for (int i = 0; i < length - 1; i++)
            {
                result.v[i] = (v[ind++] >>> r) | (v[ind] << (32 - r));
            }
            // process last word
            result.v[length - 1] = v[ind++] >>> r;
            if (ind < v.length)
            {
                result.v[length - 1] |= v[ind] << (32 - r);
            }
        }
        else
        {
            // no shift necessary
            system.arraycopy(v, q, result.v, 0, length);
        }

        return result;
    }

    /**
     * rewrite this vector as a vector over <tt>gf(2<sup>m</sup>)</tt> with
     * <tt>t</tt> elements.
     *
     * @param field the finite field <tt>gf(2<sup>m</sup>)</tt>
     * @return the converted vector over <tt>gf(2<sup>m</sup>)</tt>
     */
    public gf2mvector toextensionfieldvector(gf2mfield field)
    {
        int m = field.getdegree();
        if ((length % m) != 0)
        {
            throw new arithmeticexception("conversion is impossible");
        }

        int t = length / m;
        int[] result = new int[t];
        int count = 0;
        for (int i = t - 1; i >= 0; i--)
        {
            for (int j = field.getdegree() - 1; j >= 0; j--)
            {
                int q = count >>> 5;
                int r = count & 0x1f;

                int e = (v[q] >>> r) & 1;
                if (e == 1)
                {
                    result[i] ^= 1 << j;
                }
                count++;
            }
        }
        return new gf2mvector(field, result);
    }

    /**
     * check if the given object is equal to this vector.
     *
     * @param other vector
     * @return the result of the comparison
     */
    public boolean equals(object other)
    {

        if (!(other instanceof gf2vector))
        {
            return false;
        }
        gf2vector othervec = (gf2vector)other;

        return (length == othervec.length) && intutils.equals(v, othervec.v);
    }

    /**
     * @return the hash code of this vector
     */
    public int hashcode()
    {
        int hash = length;
        hash = hash * 31 + v.hashcode();
        return hash;
    }

    /**
     * @return a human readable form of this vector
     */
    public string tostring()
    {
        stringbuffer buf = new stringbuffer();
        for (int i = 0; i < length; i++)
        {
            if ((i != 0) && ((i & 0x1f) == 0))
            {
                buf.append(' ');
            }
            int q = i >> 5;
            int r = i & 0x1f;
            int bit = v[q] & (1 << r);
            if (bit == 0)
            {
                buf.append('0');
            }
            else
            {
                buf.append('1');
            }
        }
        return buf.tostring();
    }

}
