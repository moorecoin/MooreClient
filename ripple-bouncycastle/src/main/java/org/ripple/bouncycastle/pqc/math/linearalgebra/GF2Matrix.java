package org.ripple.bouncycastle.pqc.math.linearalgebra;

import java.security.securerandom;

/**
 * this class describes some operations with matrices over finite field gf(2)
 * and is used in ecc and mq-pkc (also has some specific methods and
 * implementation)
 */
public class gf2matrix
    extends matrix
{

    /**
     * for the matrix representation the array of type int[][] is used, thus one
     * element of the array keeps 32 elements of the matrix (from one row and 32
     * columns)
     */
    private int[][] matrix;

    /**
     * the length of each array representing a row of this matrix, computed as
     * <tt>(numcolumns + 31) / 32</tt>
     */
    private int length;

    /**
     * create the matrix from encoded form.
     *
     * @param enc the encoded matrix
     */
    public gf2matrix(byte[] enc)
    {
        if (enc.length < 9)
        {
            throw new arithmeticexception(
                "given array is not an encoded matrix over gf(2)");
        }

        numrows = littleendianconversions.os2ip(enc, 0);
        numcolumns = littleendianconversions.os2ip(enc, 4);

        int n = ((numcolumns + 7) >>> 3) * numrows;

        if ((numrows <= 0) || (n != (enc.length - 8)))
        {
            throw new arithmeticexception(
                "given array is not an encoded matrix over gf(2)");
        }

        length = (numcolumns + 31) >>> 5;
        matrix = new int[numrows][length];

        // number of "full" integer
        int q = numcolumns >> 5;
        // number of bits in non-full integer
        int r = numcolumns & 0x1f;

        int count = 8;
        for (int i = 0; i < numrows; i++)
        {
            for (int j = 0; j < q; j++, count += 4)
            {
                matrix[i][j] = littleendianconversions.os2ip(enc, count);
            }
            for (int j = 0; j < r; j += 8)
            {
                matrix[i][q] ^= (enc[count++] & 0xff) << j;
            }
        }
    }

    /**
     * create the matrix with the contents of the given array. the matrix is not
     * copied. unused coefficients are masked out.
     *
     * @param numcolumns the number of columns
     * @param matrix     the element array
     */
    public gf2matrix(int numcolumns, int[][] matrix)
    {
        if (matrix[0].length != (numcolumns + 31) >> 5)
        {
            throw new arithmeticexception(
                "int array does not match given number of columns.");
        }
        this.numcolumns = numcolumns;
        numrows = matrix.length;
        length = matrix[0].length;
        int rest = numcolumns & 0x1f;
        int bitmask;
        if (rest == 0)
        {
            bitmask = 0xffffffff;
        }
        else
        {
            bitmask = (1 << rest) - 1;
        }
        for (int i = 0; i < numrows; i++)
        {
            matrix[i][length - 1] &= bitmask;
        }
        this.matrix = matrix;
    }

    /**
     * create an nxn matrix of the given type.
     *
     * @param n            the number of rows (and columns)
     * @param typeofmatrix the martix type (see {@link matrix} for predefined
     *                     constants)
     */
    public gf2matrix(int n, char typeofmatrix)
    {
        this(n, typeofmatrix, new java.security.securerandom());
    }

    /**
     * create an nxn matrix of the given type.
     *
     * @param n            the matrix size
     * @param typeofmatrix the matrix type
     * @param sr           the source of randomness
     */
    public gf2matrix(int n, char typeofmatrix, securerandom sr)
    {
        if (n <= 0)
        {
            throw new arithmeticexception("size of matrix is non-positive.");
        }

        switch (typeofmatrix)
        {

        case matrix.matrix_type_zero:
            assignzeromatrix(n, n);
            break;

        case matrix.matrix_type_unit:
            assignunitmatrix(n);
            break;

        case matrix.matrix_type_random_lt:
            assignrandomlowertriangularmatrix(n, sr);
            break;

        case matrix.matrix_type_random_ut:
            assignrandomuppertriangularmatrix(n, sr);
            break;

        case matrix.matrix_type_random_regular:
            assignrandomregularmatrix(n, sr);
            break;

        default:
            throw new arithmeticexception("unknown matrix type.");
        }
    }

    /**
     * copy constructor.
     *
     * @param a another {@link gf2matrix}
     */
    public gf2matrix(gf2matrix a)
    {
        numcolumns = a.getnumcolumns();
        numrows = a.getnumrows();
        length = a.length;
        matrix = new int[a.matrix.length][];
        for (int i = 0; i < matrix.length; i++)
        {
            matrix[i] = intutils.clone(a.matrix[i]);
        }

    }

    /**
     * create the mxn zero matrix
     */
    private gf2matrix(int m, int n)
    {
        if ((n <= 0) || (m <= 0))
        {
            throw new arithmeticexception("size of matrix is non-positive");
        }

        assignzeromatrix(m, n);
    }

    /**
     * create the mxn zero matrix.
     *
     * @param m number of rows
     * @param n number of columns
     */
    private void assignzeromatrix(int m, int n)
    {
        numrows = m;
        numcolumns = n;
        length = (n + 31) >>> 5;
        matrix = new int[numrows][length];
        for (int i = 0; i < numrows; i++)
        {
            for (int j = 0; j < length; j++)
            {
                matrix[i][j] = 0;
            }
        }
    }

    /**
     * create the mxn unit matrix.
     *
     * @param n number of rows (and columns)
     */
    private void assignunitmatrix(int n)
    {
        numrows = n;
        numcolumns = n;
        length = (n + 31) >>> 5;
        matrix = new int[numrows][length];
        for (int i = 0; i < numrows; i++)
        {
            for (int j = 0; j < length; j++)
            {
                matrix[i][j] = 0;
            }
        }
        for (int i = 0; i < numrows; i++)
        {
            int rest = i & 0x1f;
            matrix[i][i >>> 5] = 1 << rest;
        }
    }

    /**
     * create a nxn random lower triangular matrix.
     *
     * @param n  number of rows (and columns)
     * @param sr source of randomness
     */
    private void assignrandomlowertriangularmatrix(int n, securerandom sr)
    {
        numrows = n;
        numcolumns = n;
        length = (n + 31) >>> 5;
        matrix = new int[numrows][length];
        for (int i = 0; i < numrows; i++)
        {
            int q = i >>> 5;
            int r = i & 0x1f;
            int s = 31 - r;
            r = 1 << r;
            for (int j = 0; j < q; j++)
            {
                matrix[i][j] = sr.nextint();
            }
            matrix[i][q] = (sr.nextint() >>> s) | r;
            for (int j = q + 1; j < length; j++)
            {
                matrix[i][j] = 0;
            }

        }

    }

    /**
     * create a nxn random upper triangular matrix.
     *
     * @param n  number of rows (and columns)
     * @param sr source of randomness
     */
    private void assignrandomuppertriangularmatrix(int n, securerandom sr)
    {
        numrows = n;
        numcolumns = n;
        length = (n + 31) >>> 5;
        matrix = new int[numrows][length];
        int rest = n & 0x1f;
        int help;
        if (rest == 0)
        {
            help = 0xffffffff;
        }
        else
        {
            help = (1 << rest) - 1;
        }
        for (int i = 0; i < numrows; i++)
        {
            int q = i >>> 5;
            int r = i & 0x1f;
            int s = r;
            r = 1 << r;
            for (int j = 0; j < q; j++)
            {
                matrix[i][j] = 0;
            }
            matrix[i][q] = (sr.nextint() << s) | r;
            for (int j = q + 1; j < length; j++)
            {
                matrix[i][j] = sr.nextint();
            }
            matrix[i][length - 1] &= help;
        }

    }

    /**
     * create an nxn random regular matrix.
     *
     * @param n  number of rows (and columns)
     * @param sr source of randomness
     */
    private void assignrandomregularmatrix(int n, securerandom sr)
    {
        numrows = n;
        numcolumns = n;
        length = (n + 31) >>> 5;
        matrix = new int[numrows][length];
        gf2matrix lm = new gf2matrix(n, matrix.matrix_type_random_lt, sr);
        gf2matrix um = new gf2matrix(n, matrix.matrix_type_random_ut, sr);
        gf2matrix rm = (gf2matrix)lm.rightmultiply(um);
        permutation perm = new permutation(n, sr);
        int[] p = perm.getvector();
        for (int i = 0; i < n; i++)
        {
            system.arraycopy(rm.matrix[i], 0, matrix[p[i]], 0, length);
        }
    }

    /**
     * create a nxn random regular matrix and its inverse.
     *
     * @param n  number of rows (and columns)
     * @param sr source of randomness
     * @return the created random regular matrix and its inverse
     */
    public static gf2matrix[] createrandomregularmatrixanditsinverse(int n,
                                                                     securerandom sr)
    {

        gf2matrix[] result = new gf2matrix[2];

        // ------------------------------------
        // first part: create regular matrix
        // ------------------------------------

        // ------
        int length = (n + 31) >> 5;
        gf2matrix lm = new gf2matrix(n, matrix.matrix_type_random_lt, sr);
        gf2matrix um = new gf2matrix(n, matrix.matrix_type_random_ut, sr);
        gf2matrix rm = (gf2matrix)lm.rightmultiply(um);
        permutation p = new permutation(n, sr);
        int[] pvec = p.getvector();

        int[][] matrix = new int[n][length];
        for (int i = 0; i < n; i++)
        {
            system.arraycopy(rm.matrix[pvec[i]], 0, matrix[i], 0, length);
        }

        result[0] = new gf2matrix(n, matrix);

        // ------------------------------------
        // second part: create inverse matrix
        // ------------------------------------

        // inverse to lm
        gf2matrix invlm = new gf2matrix(n, matrix.matrix_type_unit);
        for (int i = 0; i < n; i++)
        {
            int rest = i & 0x1f;
            int q = i >>> 5;
            int r = 1 << rest;
            for (int j = i + 1; j < n; j++)
            {
                int b = (lm.matrix[j][q]) & r;
                if (b != 0)
                {
                    for (int k = 0; k <= q; k++)
                    {
                        invlm.matrix[j][k] ^= invlm.matrix[i][k];
                    }
                }
            }
        }
        // inverse to um
        gf2matrix invum = new gf2matrix(n, matrix.matrix_type_unit);
        for (int i = n - 1; i >= 0; i--)
        {
            int rest = i & 0x1f;
            int q = i >>> 5;
            int r = 1 << rest;
            for (int j = i - 1; j >= 0; j--)
            {
                int b = (um.matrix[j][q]) & r;
                if (b != 0)
                {
                    for (int k = q; k < length; k++)
                    {
                        invum.matrix[j][k] ^= invum.matrix[i][k];
                    }
                }
            }
        }

        // inverse matrix
        result[1] = (gf2matrix)invum.rightmultiply(invlm.rightmultiply(p));

        return result;
    }

    /**
     * @return the array keeping the matrix elements
     */
    public int[][] getintarray()
    {
        return matrix;
    }

    /**
     * @return the length of each array representing a row of this matrix
     */
    public int getlength()
    {
        return length;
    }

    /**
     * return the row of this matrix with the given index.
     *
     * @param index the index
     * @return the row of this matrix with the given index
     */
    public int[] getrow(int index)
    {
        return matrix[index];
    }

    /**
     * returns encoded matrix, i.e., this matrix in byte array form
     *
     * @return the encoded matrix
     */
    public byte[] getencoded()
    {
        int n = (numcolumns + 7) >>> 3;
        n *= numrows;
        n += 8;
        byte[] enc = new byte[n];

        littleendianconversions.i2osp(numrows, enc, 0);
        littleendianconversions.i2osp(numcolumns, enc, 4);

        // number of "full" integer
        int q = numcolumns >>> 5;
        // number of bits in non-full integer
        int r = numcolumns & 0x1f;

        int count = 8;
        for (int i = 0; i < numrows; i++)
        {
            for (int j = 0; j < q; j++, count += 4)
            {
                littleendianconversions.i2osp(matrix[i][j], enc, count);
            }
            for (int j = 0; j < r; j += 8)
            {
                enc[count++] = (byte)((matrix[i][q] >>> j) & 0xff);
            }

        }
        return enc;
    }


    /**
     * returns the percentage of the number of "ones" in this matrix.
     *
     * @return the hamming weight of this matrix (as a ratio).
     */
    public double gethammingweight()
    {
        double counter = 0.0;
        double elementcounter = 0.0;
        int rest = numcolumns & 0x1f;
        int d;
        if (rest == 0)
        {
            d = length;
        }
        else
        {
            d = length - 1;
        }

        for (int i = 0; i < numrows; i++)
        {

            for (int j = 0; j < d; j++)
            {
                int a = matrix[i][j];
                for (int k = 0; k < 32; k++)
                {
                    int b = (a >>> k) & 1;
                    counter = counter + b;
                    elementcounter = elementcounter + 1;
                }
            }
            int a = matrix[i][length - 1];
            for (int k = 0; k < rest; k++)
            {
                int b = (a >>> k) & 1;
                counter = counter + b;
                elementcounter = elementcounter + 1;
            }
        }

        return counter / elementcounter;
    }

    /**
     * check if this is the zero matrix (i.e., all entries are zero).
     *
     * @return <tt>true</tt> if this is the zero matrix
     */
    public boolean iszero()
    {
        for (int i = 0; i < numrows; i++)
        {
            for (int j = 0; j < length; j++)
            {
                if (matrix[i][j] != 0)
                {
                    return false;
                }
            }
        }
        return true;
    }

    /**
     * get the quadratic submatrix of this matrix consisting of the leftmost
     * <tt>numrows</tt> columns.
     *
     * @return the <tt>(numrows x numrows)</tt> submatrix
     */
    public gf2matrix getleftsubmatrix()
    {
        if (numcolumns <= numrows)
        {
            throw new arithmeticexception("empty submatrix");
        }
        int length = (numrows + 31) >> 5;
        int[][] result = new int[numrows][length];
        int bitmask = (1 << (numrows & 0x1f)) - 1;
        if (bitmask == 0)
        {
            bitmask = -1;
        }
        for (int i = numrows - 1; i >= 0; i--)
        {
            system.arraycopy(matrix[i], 0, result[i], 0, length);
            result[i][length - 1] &= bitmask;
        }
        return new gf2matrix(numrows, result);
    }

    /**
     * compute the full form matrix <tt>(this | id)</tt> from this matrix in
     * left compact form, where <tt>id</tt> is the <tt>k x k</tt> identity
     * matrix and <tt>k</tt> is the number of rows of this matrix.
     *
     * @return <tt>(this | id)</tt>
     */
    public gf2matrix extendleftcompactform()
    {
        int newnumcolumns = numcolumns + numrows;
        gf2matrix result = new gf2matrix(numrows, newnumcolumns);

        int ind = numrows - 1 + numcolumns;
        for (int i = numrows - 1; i >= 0; i--, ind--)
        {
            // copy this matrix to first columns
            system.arraycopy(matrix[i], 0, result.matrix[i], 0, length);
            // store the identity in last columns
            result.matrix[i][ind >> 5] |= 1 << (ind & 0x1f);
        }

        return result;
    }

    /**
     * get the submatrix of this matrix consisting of the rightmost
     * <tt>numcolumns-numrows</tt> columns.
     *
     * @return the <tt>(numrows x (numcolumns-numrows))</tt> submatrix
     */
    public gf2matrix getrightsubmatrix()
    {
        if (numcolumns <= numrows)
        {
            throw new arithmeticexception("empty submatrix");
        }

        int q = numrows >> 5;
        int r = numrows & 0x1f;

        gf2matrix result = new gf2matrix(numrows, numcolumns - numrows);

        for (int i = numrows - 1; i >= 0; i--)
        {
            // if words have to be shifted
            if (r != 0)
            {
                int ind = q;
                // process all but last word
                for (int j = 0; j < result.length - 1; j++)
                {
                    // shift to correct position
                    result.matrix[i][j] = (matrix[i][ind++] >>> r)
                        | (matrix[i][ind] << (32 - r));
                }
                // process last word
                result.matrix[i][result.length - 1] = matrix[i][ind++] >>> r;
                if (ind < length)
                {
                    result.matrix[i][result.length - 1] |= matrix[i][ind] << (32 - r);
                }
            }
            else
            {
                // no shifting necessary
                system.arraycopy(matrix[i], q, result.matrix[i], 0,
                    result.length);
            }
        }
        return result;
    }

    /**
     * compute the full form matrix <tt>(id | this)</tt> from this matrix in
     * right compact form, where <tt>id</tt> is the <tt>k x k</tt> identity
     * matrix and <tt>k</tt> is the number of rows of this matrix.
     *
     * @return <tt>(id | this)</tt>
     */
    public gf2matrix extendrightcompactform()
    {
        gf2matrix result = new gf2matrix(numrows, numrows + numcolumns);

        int q = numrows >> 5;
        int r = numrows & 0x1f;

        for (int i = numrows - 1; i >= 0; i--)
        {
            // store the identity in first columns
            result.matrix[i][i >> 5] |= 1 << (i & 0x1f);

            // copy this matrix to last columns

            // if words have to be shifted
            if (r != 0)
            {
                int ind = q;
                // process all but last word
                for (int j = 0; j < length - 1; j++)
                {
                    // obtain matrix word
                    int mw = matrix[i][j];
                    // shift to correct position
                    result.matrix[i][ind++] |= mw << r;
                    result.matrix[i][ind] |= mw >>> (32 - r);
                }
                // process last word
                int mw = matrix[i][length - 1];
                result.matrix[i][ind++] |= mw << r;
                if (ind < result.length)
                {
                    result.matrix[i][ind] |= mw >>> (32 - r);
                }
            }
            else
            {
                // no shifting necessary
                system.arraycopy(matrix[i], 0, result.matrix[i], q, length);
            }
        }

        return result;
    }

    /**
     * compute the transpose of this matrix.
     *
     * @return <tt>(this)<sup>t</sup></tt>
     */
    public matrix computetranspose()
    {
        int[][] result = new int[numcolumns][(numrows + 31) >>> 5];
        for (int i = 0; i < numrows; i++)
        {
            for (int j = 0; j < numcolumns; j++)
            {
                int qs = j >>> 5;
                int rs = j & 0x1f;
                int b = (matrix[i][qs] >>> rs) & 1;
                int qt = i >>> 5;
                int rt = i & 0x1f;
                if (b == 1)
                {
                    result[j][qt] |= 1 << rt;
                }
            }
        }

        return new gf2matrix(numrows, result);
    }

    /**
     * compute the inverse of this matrix.
     *
     * @return the inverse of this matrix (newly created).
     * @throws arithmeticexception if this matrix is not invertible.
     */
    public matrix computeinverse()
    {
        if (numrows != numcolumns)
        {
            throw new arithmeticexception("matrix is not invertible.");
        }

        // clone this matrix
        int[][] tmpmatrix = new int[numrows][length];
        for (int i = numrows - 1; i >= 0; i--)
        {
            tmpmatrix[i] = intutils.clone(matrix[i]);
        }

        // initialize inverse matrix as unit matrix
        int[][] invmatrix = new int[numrows][length];
        for (int i = numrows - 1; i >= 0; i--)
        {
            int q = i >> 5;
            int r = i & 0x1f;
            invmatrix[i][q] = 1 << r;
        }

        // simultaneously compute gaussian reduction of tmpmatrix and unit
        // matrix
        for (int i = 0; i < numrows; i++)
        {
            // i = q * 32 + (i mod 32)
            int q = i >> 5;
            int bitmask = 1 << (i & 0x1f);
            // if diagonal element is zero
            if ((tmpmatrix[i][q] & bitmask) == 0)
            {
                boolean foundnonzero = false;
                // find a non-zero element in the same column
                for (int j = i + 1; j < numrows; j++)
                {
                    if ((tmpmatrix[j][q] & bitmask) != 0)
                    {
                        // found it, swap rows ...
                        foundnonzero = true;
                        swaprows(tmpmatrix, i, j);
                        swaprows(invmatrix, i, j);
                        // ... and quit searching
                        j = numrows;
                        continue;
                    }
                }
                // if no non-zero element was found ...
                if (!foundnonzero)
                {
                    // ... the matrix is not invertible
                    throw new arithmeticexception("matrix is not invertible.");
                }
            }

            // normalize all but i-th row
            for (int j = numrows - 1; j >= 0; j--)
            {
                if ((j != i) && ((tmpmatrix[j][q] & bitmask) != 0))
                {
                    addtorow(tmpmatrix[i], tmpmatrix[j], q);
                    addtorow(invmatrix[i], invmatrix[j], 0);
                }
            }
        }

        return new gf2matrix(numcolumns, invmatrix);
    }

    /**
     * compute the product of a permutation matrix (which is generated from an
     * n-permutation) and this matrix.
     *
     * @param p the permutation
     * @return {@link gf2matrix} <tt>p*this</tt>
     */
    public matrix leftmultiply(permutation p)
    {
        int[] pvec = p.getvector();
        if (pvec.length != numrows)
        {
            throw new arithmeticexception("length mismatch");
        }

        int[][] result = new int[numrows][];

        for (int i = numrows - 1; i >= 0; i--)
        {
            result[i] = intutils.clone(matrix[pvec[i]]);
        }

        return new gf2matrix(numrows, result);
    }

    /**
     * compute product a row vector and this matrix
     *
     * @param vec a vector over gf(2)
     * @return vector product a*matrix
     */
    public vector leftmultiply(vector vec)
    {

        if (!(vec instanceof gf2vector))
        {
            throw new arithmeticexception("vector is not defined over gf(2)");
        }

        if (vec.length != numrows)
        {
            throw new arithmeticexception("length mismatch");
        }

        int[] v = ((gf2vector)vec).getvecarray();
        int[] res = new int[length];

        int q = numrows >> 5;
        int r = 1 << (numrows & 0x1f);

        // compute scalar products with full words of vector
        int row = 0;
        for (int i = 0; i < q; i++)
        {
            int bitmask = 1;
            do
            {
                int b = v[i] & bitmask;
                if (b != 0)
                {
                    for (int j = 0; j < length; j++)
                    {
                        res[j] ^= matrix[row][j];
                    }
                }
                row++;
                bitmask <<= 1;
            }
            while (bitmask != 0);
        }

        // compute scalar products with last word of vector
        int bitmask = 1;
        while (bitmask != r)
        {
            int b = v[q] & bitmask;
            if (b != 0)
            {
                for (int j = 0; j < length; j++)
                {
                    res[j] ^= matrix[row][j];
                }
            }
            row++;
            bitmask <<= 1;
        }

        return new gf2vector(res, numcolumns);
    }

    /**
     * compute the product of the matrix <tt>(this | id)</tt> and a column
     * vector, where <tt>id</tt> is a <tt>(numrows x numrows)</tt> unit
     * matrix.
     *
     * @param vec the vector over gf(2)
     * @return <tt>(this | id)*vector</tt>
     */
    public vector leftmultiplyleftcompactform(vector vec)
    {
        if (!(vec instanceof gf2vector))
        {
            throw new arithmeticexception("vector is not defined over gf(2)");
        }

        if (vec.length != numrows)
        {
            throw new arithmeticexception("length mismatch");
        }

        int[] v = ((gf2vector)vec).getvecarray();
        int[] res = new int[(numrows + numcolumns + 31) >>> 5];

        // process full words of vector
        int words = numrows >>> 5;
        int row = 0;
        for (int i = 0; i < words; i++)
        {
            int bitmask = 1;
            do
            {
                int b = v[i] & bitmask;
                if (b != 0)
                {
                    // compute scalar product part
                    for (int j = 0; j < length; j++)
                    {
                        res[j] ^= matrix[row][j];
                    }
                    // set last bit
                    int q = (numcolumns + row) >>> 5;
                    int r = (numcolumns + row) & 0x1f;
                    res[q] |= 1 << r;
                }
                row++;
                bitmask <<= 1;
            }
            while (bitmask != 0);
        }

        // process last word of vector
        int rem = 1 << (numrows & 0x1f);
        int bitmask = 1;
        while (bitmask != rem)
        {
            int b = v[words] & bitmask;
            if (b != 0)
            {
                // compute scalar product part
                for (int j = 0; j < length; j++)
                {
                    res[j] ^= matrix[row][j];
                }
                // set last bit
                int q = (numcolumns + row) >>> 5;
                int r = (numcolumns + row) & 0x1f;
                res[q] |= 1 << r;
            }
            row++;
            bitmask <<= 1;
        }

        return new gf2vector(res, numrows + numcolumns);
    }

    /**
     * compute the product of this matrix and a matrix a over gf(2).
     *
     * @param mat a matrix a over gf(2)
     * @return matrix product <tt>this*matrixa</tt>
     */
    public matrix rightmultiply(matrix mat)
    {
        if (!(mat instanceof gf2matrix))
        {
            throw new arithmeticexception("matrix is not defined over gf(2)");
        }

        if (mat.numrows != numcolumns)
        {
            throw new arithmeticexception("length mismatch");
        }

        gf2matrix a = (gf2matrix)mat;
        gf2matrix result = new gf2matrix(numrows, mat.numcolumns);

        int d;
        int rest = numcolumns & 0x1f;
        if (rest == 0)
        {
            d = length;
        }
        else
        {
            d = length - 1;
        }
        for (int i = 0; i < numrows; i++)
        {
            int count = 0;
            for (int j = 0; j < d; j++)
            {
                int e = matrix[i][j];
                for (int h = 0; h < 32; h++)
                {
                    int b = e & (1 << h);
                    if (b != 0)
                    {
                        for (int g = 0; g < a.length; g++)
                        {
                            result.matrix[i][g] ^= a.matrix[count][g];
                        }
                    }
                    count++;
                }
            }
            int e = matrix[i][length - 1];
            for (int h = 0; h < rest; h++)
            {
                int b = e & (1 << h);
                if (b != 0)
                {
                    for (int g = 0; g < a.length; g++)
                    {
                        result.matrix[i][g] ^= a.matrix[count][g];
                    }
                }
                count++;
            }

        }

        return result;
    }

    /**
     * compute the product of this matrix and a permutation matrix which is
     * generated from an n-permutation.
     *
     * @param p the permutation
     * @return {@link gf2matrix} <tt>this*p</tt>
     */
    public matrix rightmultiply(permutation p)
    {

        int[] pvec = p.getvector();
        if (pvec.length != numcolumns)
        {
            throw new arithmeticexception("length mismatch");
        }

        gf2matrix result = new gf2matrix(numrows, numcolumns);

        for (int i = numcolumns - 1; i >= 0; i--)
        {
            int q = i >>> 5;
            int r = i & 0x1f;
            int pq = pvec[i] >>> 5;
            int pr = pvec[i] & 0x1f;
            for (int j = numrows - 1; j >= 0; j--)
            {
                result.matrix[j][q] |= ((matrix[j][pq] >>> pr) & 1) << r;
            }
        }

        return result;
    }

    /**
     * compute the product of this matrix and the given column vector.
     *
     * @param vec the vector over gf(2)
     * @return <tt>this*vector</tt>
     */
    public vector rightmultiply(vector vec)
    {
        if (!(vec instanceof gf2vector))
        {
            throw new arithmeticexception("vector is not defined over gf(2)");
        }

        if (vec.length != numcolumns)
        {
            throw new arithmeticexception("length mismatch");
        }

        int[] v = ((gf2vector)vec).getvecarray();
        int[] res = new int[(numrows + 31) >>> 5];

        for (int i = 0; i < numrows; i++)
        {
            // compute full word scalar products
            int help = 0;
            for (int j = 0; j < length; j++)
            {
                help ^= matrix[i][j] & v[j];
            }
            // compute single word scalar product
            int bitvalue = 0;
            for (int j = 0; j < 32; j++)
            {
                bitvalue ^= (help >>> j) & 1;
            }
            // set result bit
            if (bitvalue == 1)
            {
                res[i >>> 5] |= 1 << (i & 0x1f);
            }
        }

        return new gf2vector(res, numrows);
    }

    /**
     * compute the product of the matrix <tt>(id | this)</tt> and a column
     * vector, where <tt>id</tt> is a <tt>(numrows x numrows)</tt> unit
     * matrix.
     *
     * @param vec the vector over gf(2)
     * @return <tt>(id | this)*vector</tt>
     */
    public vector rightmultiplyrightcompactform(vector vec)
    {
        if (!(vec instanceof gf2vector))
        {
            throw new arithmeticexception("vector is not defined over gf(2)");
        }

        if (vec.length != numcolumns + numrows)
        {
            throw new arithmeticexception("length mismatch");
        }

        int[] v = ((gf2vector)vec).getvecarray();
        int[] res = new int[(numrows + 31) >>> 5];

        int q = numrows >> 5;
        int r = numrows & 0x1f;

        // for all rows
        for (int i = 0; i < numrows; i++)
        {
            // get vector bit
            int help = (v[i >> 5] >>> (i & 0x1f)) & 1;

            // compute full word scalar products
            int vind = q;
            // if words have to be shifted
            if (r != 0)
            {
                int vw = 0;
                // process all but last word
                for (int j = 0; j < length - 1; j++)
                {
                    // shift to correct position
                    vw = (v[vind++] >>> r) | (v[vind] << (32 - r));
                    help ^= matrix[i][j] & vw;
                }
                // process last word
                vw = v[vind++] >>> r;
                if (vind < v.length)
                {
                    vw |= v[vind] << (32 - r);
                }
                help ^= matrix[i][length - 1] & vw;
            }
            else
            {
                // no shifting necessary
                for (int j = 0; j < length; j++)
                {
                    help ^= matrix[i][j] & v[vind++];
                }
            }

            // compute single word scalar product
            int bitvalue = 0;
            for (int j = 0; j < 32; j++)
            {
                bitvalue ^= help & 1;
                help >>>= 1;
            }

            // set result bit
            if (bitvalue == 1)
            {
                res[i >> 5] |= 1 << (i & 0x1f);
            }
        }

        return new gf2vector(res, numrows);
    }

    /**
     * compare this matrix with another object.
     *
     * @param other another object
     * @return the result of the comparison
     */
    public boolean equals(object other)
    {

        if (!(other instanceof gf2matrix))
        {
            return false;
        }
        gf2matrix othermatrix = (gf2matrix)other;

        if ((numrows != othermatrix.numrows)
            || (numcolumns != othermatrix.numcolumns)
            || (length != othermatrix.length))
        {
            return false;
        }

        for (int i = 0; i < numrows; i++)
        {
            if (!intutils.equals(matrix[i], othermatrix.matrix[i]))
            {
                return false;
            }
        }

        return true;
    }

    /**
     * @return the hash code of this matrix
     */
    public int hashcode()
    {
        int hash = (numrows * 31 + numcolumns) * 31 + length;
        for (int i = 0; i < numrows; i++)
        {
            hash = hash * 31 + matrix[i].hashcode();
        }
        return hash;
    }

    /**
     * @return a human readable form of the matrix
     */
    public string tostring()
    {
        int rest = numcolumns & 0x1f;
        int d;
        if (rest == 0)
        {
            d = length;
        }
        else
        {
            d = length - 1;
        }

        stringbuffer buf = new stringbuffer();
        for (int i = 0; i < numrows; i++)
        {
            buf.append(i + ": ");
            for (int j = 0; j < d; j++)
            {
                int a = matrix[i][j];
                for (int k = 0; k < 32; k++)
                {
                    int b = (a >>> k) & 1;
                    if (b == 0)
                    {
                        buf.append('0');
                    }
                    else
                    {
                        buf.append('1');
                    }
                }
                buf.append(' ');
            }
            int a = matrix[i][length - 1];
            for (int k = 0; k < rest; k++)
            {
                int b = (a >>> k) & 1;
                if (b == 0)
                {
                    buf.append('0');
                }
                else
                {
                    buf.append('1');
                }
            }
            buf.append('\n');
        }

        return buf.tostring();
    }

    /**
     * swap two rows of the given matrix.
     *
     * @param matrix the matrix
     * @param first  the index of the first row
     * @param second the index of the second row
     */
    private static void swaprows(int[][] matrix, int first, int second)
    {
        int[] tmp = matrix[first];
        matrix[first] = matrix[second];
        matrix[second] = tmp;
    }

    /**
     * partially add one row to another.
     *
     * @param fromrow    the addend
     * @param torow      the row to add to
     * @param startindex the array index to start from
     */
    private static void addtorow(int[] fromrow, int[] torow, int startindex)
    {
        for (int i = torow.length - 1; i >= startindex; i--)
        {
            torow[i] = fromrow[i] ^ torow[i];
        }
    }

}
