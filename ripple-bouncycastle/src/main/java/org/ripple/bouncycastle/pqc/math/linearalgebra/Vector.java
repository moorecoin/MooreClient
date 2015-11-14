package org.ripple.bouncycastle.pqc.math.linearalgebra;

/**
 * this abstract class defines vectors. it holds the length of vector.
 */
public abstract class vector
{

    /**
     * the length of this vector
     */
    protected int length;

    /**
     * @return the length of this vector
     */
    public final int getlength()
    {
        return length;
    }

    /**
     * @return this vector as byte array
     */
    public abstract byte[] getencoded();

    /**
     * return whether this is the zero vector (i.e., all elements are zero).
     *
     * @return <tt>true</tt> if this is the zero vector, <tt>false</tt>
     *         otherwise
     */
    public abstract boolean iszero();

    /**
     * add another vector to this vector.
     *
     * @param addend the other vector
     * @return <tt>this + addend</tt>
     */
    public abstract vector add(vector addend);

    /**
     * multiply this vector with a permutation.
     *
     * @param p the permutation
     * @return <tt>this*p = p*this</tt>
     */
    public abstract vector multiply(permutation p);

    /**
     * check if the given object is equal to this vector.
     *
     * @param other vector
     * @return the result of the comparison
     */
    public abstract boolean equals(object other);

    /**
     * @return the hash code of this vector
     */
    public abstract int hashcode();

    /**
     * @return a human readable form of this vector
     */
    public abstract string tostring();

}
