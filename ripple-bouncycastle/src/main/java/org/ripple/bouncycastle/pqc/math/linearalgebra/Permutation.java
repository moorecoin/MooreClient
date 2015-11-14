package org.ripple.bouncycastle.pqc.math.linearalgebra;

import java.security.securerandom;

/**
 * this class implements permutations of the set {0,1,...,n-1} for some given n
 * &gt; 0, i.e., ordered sequences containing each number <tt>m</tt> (<tt>0 &lt;=
 * m &lt; n</tt>)
 * once and only once.
 */
public class permutation
{

    /**
     * perm holds the elements of the permutation vector, i.e. <tt>[perm(0),
     * perm(1), ..., perm(n-1)]</tt>
     */
    private int[] perm;

    /**
     * create the identity permutation of the given size.
     *
     * @param n the size of the permutation
     */
    public permutation(int n)
    {
        if (n <= 0)
        {
            throw new illegalargumentexception("invalid length");
        }

        perm = new int[n];
        for (int i = n - 1; i >= 0; i--)
        {
            perm[i] = i;
        }
    }

    /**
     * create a permutation using the given permutation vector.
     *
     * @param perm the permutation vector
     */
    public permutation(int[] perm)
    {
        if (!ispermutation(perm))
        {
            throw new illegalargumentexception(
                "array is not a permutation vector");
        }

        this.perm = intutils.clone(perm);
    }

    /**
     * create a permutation from an encoded permutation.
     *
     * @param enc the encoded permutation
     */
    public permutation(byte[] enc)
    {
        if (enc.length <= 4)
        {
            throw new illegalargumentexception("invalid encoding");
        }

        int n = littleendianconversions.os2ip(enc, 0);
        int size = integerfunctions.ceillog256(n - 1);

        if (enc.length != 4 + n * size)
        {
            throw new illegalargumentexception("invalid encoding");
        }

        perm = new int[n];
        for (int i = 0; i < n; i++)
        {
            perm[i] = littleendianconversions.os2ip(enc, 4 + i * size, size);
        }

        if (!ispermutation(perm))
        {
            throw new illegalargumentexception("invalid encoding");
        }

    }

    /**
     * create a random permutation of the given size.
     *
     * @param n  the size of the permutation
     * @param sr the source of randomness
     */
    public permutation(int n, securerandom sr)
    {
        if (n <= 0)
        {
            throw new illegalargumentexception("invalid length");
        }

        perm = new int[n];

        int[] help = new int[n];
        for (int i = 0; i < n; i++)
        {
            help[i] = i;
        }

        int k = n;
        for (int j = 0; j < n; j++)
        {
            int i = randutils.nextint(sr, k);
            k--;
            perm[j] = help[i];
            help[i] = help[k];
        }
    }

    /**
     * encode this permutation as byte array.
     *
     * @return the encoded permutation
     */
    public byte[] getencoded()
    {
        int n = perm.length;
        int size = integerfunctions.ceillog256(n - 1);
        byte[] result = new byte[4 + n * size];
        littleendianconversions.i2osp(n, result, 0);
        for (int i = 0; i < n; i++)
        {
            littleendianconversions.i2osp(perm[i], result, 4 + i * size, size);
        }
        return result;
    }

    /**
     * @return the permutation vector <tt>(perm(0),perm(1),...,perm(n-1))</tt>
     */
    public int[] getvector()
    {
        return intutils.clone(perm);
    }

    /**
     * compute the inverse permutation <tt>p<sup>-1</sup></tt>.
     *
     * @return <tt>this<sup>-1</sup></tt>
     */
    public permutation computeinverse()
    {
        permutation result = new permutation(perm.length);
        for (int i = perm.length - 1; i >= 0; i--)
        {
            result.perm[perm[i]] = i;
        }
        return result;
    }

    /**
     * compute the product of this permutation and another permutation.
     *
     * @param p the other permutation
     * @return <tt>this * p</tt>
     */
    public permutation rightmultiply(permutation p)
    {
        if (p.perm.length != perm.length)
        {
            throw new illegalargumentexception("length mismatch");
        }
        permutation result = new permutation(perm.length);
        for (int i = perm.length - 1; i >= 0; i--)
        {
            result.perm[i] = perm[p.perm[i]];
        }
        return result;
    }

    /**
     * checks if given object is equal to this permutation.
     * <p/>
     * the method returns false whenever the given object is not permutation.
     *
     * @param other -
     *              permutation
     * @return true or false
     */
    public boolean equals(object other)
    {

        if (!(other instanceof permutation))
        {
            return false;
        }
        permutation otherperm = (permutation)other;

        return intutils.equals(perm, otherperm.perm);
    }

    /**
     * @return a human readable form of the permutation
     */
    public string tostring()
    {
        string result = "[" + perm[0];
        for (int i = 1; i < perm.length; i++)
        {
            result += ", " + perm[i];
        }
        result += "]";
        return result;
    }

    /**
     * @return the hash code of this permutation
     */
    public int hashcode()
    {
        return perm.hashcode();
    }

    /**
     * check that the given array corresponds to a permutation of the set
     * <tt>{0, 1, ..., n-1}</tt>.
     *
     * @param perm permutation vector
     * @return true if perm represents an n-permutation and false otherwise
     */
    private boolean ispermutation(int[] perm)
    {
        int n = perm.length;
        boolean[] onlyonce = new boolean[n];

        for (int i = 0; i < n; i++)
        {
            if ((perm[i] < 0) || (perm[i] >= n) || onlyonce[perm[i]])
            {
                return false;
            }
            onlyonce[perm[i]] = true;
        }

        return true;
    }

}
