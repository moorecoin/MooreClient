package org.ripple.bouncycastle.pqc.math.linearalgebra;

/**
 * this abstract class defines matrices. it holds the number of rows and the
 * number of columns of the matrix and defines some basic methods.
 */
public abstract class matrix
{

    /**
     * number of rows
     */
    protected int numrows;

    /**
     * number of columns
     */
    protected int numcolumns;

    // ----------------------------------------------------
    // some constants (matrix types)
    // ----------------------------------------------------

    /**
     * zero matrix
     */
    public static final char matrix_type_zero = 'z';

    /**
     * unit matrix
     */
    public static final char matrix_type_unit = 'i';

    /**
     * random lower triangular matrix
     */
    public static final char matrix_type_random_lt = 'l';

    /**
     * random upper triangular matrix
     */
    public static final char matrix_type_random_ut = 'u';

    /**
     * random regular matrix
     */
    public static final char matrix_type_random_regular = 'r';

    // ----------------------------------------------------
    // getters
    // ----------------------------------------------------

    /**
     * @return the number of rows in the matrix
     */
    public int getnumrows()
    {
        return numrows;
    }

    /**
     * @return the number of columns in the binary matrix
     */
    public int getnumcolumns()
    {
        return numcolumns;
    }

    /**
     * @return the encoded matrix, i.e., this matrix in byte array form.
     */
    public abstract byte[] getencoded();

    // ----------------------------------------------------
    // arithmetic
    // ----------------------------------------------------

    /**
     * compute the inverse of this matrix.
     *
     * @return the inverse of this matrix (newly created).
     */
    public abstract matrix computeinverse();

    /**
     * check if this is the zero matrix (i.e., all entries are zero).
     *
     * @return <tt>true</tt> if this is the zero matrix
     */
    public abstract boolean iszero();

    /**
     * compute the product of this matrix and another matrix.
     *
     * @param a the other matrix
     * @return <tt>this * a</tt> (newly created)
     */
    public abstract matrix rightmultiply(matrix a);

    /**
     * compute the product of this matrix and a permutation.
     *
     * @param p the permutation
     * @return <tt>this * p</tt> (newly created)
     */
    public abstract matrix rightmultiply(permutation p);

    /**
     * compute the product of a vector and this matrix. if the length of the
     * vector is greater than the number of rows of this matrix, the matrix is
     * multiplied by each m-bit part of the vector.
     *
     * @param vector a vector
     * @return <tt>vector * this</tt> (newly created)
     */
    public abstract vector leftmultiply(vector vector);

    /**
     * compute the product of this matrix and a vector.
     *
     * @param vector a vector
     * @return <tt>this * vector</tt> (newly created)
     */
    public abstract vector rightmultiply(vector vector);

    /**
     * @return a human readable form of the matrix.
     */
    public abstract string tostring();

}
