package org.ripple.bouncycastle.pqc.crypto.rainbow.util;

/**
 * this class offers different operations on matrices in field gf2^8.
 * <p/>
 * implemented are functions:
 * - finding inverse of a matrix
 * - solving linear equation systems using the gauss-elimination method
 * - basic operations like matrix multiplication, addition and so on.
 */

public class computeinfield
{

    private short[][] a; // used by solveequation and inverse
    short[] x;

    /**
     * constructor with no parameters
     */
    public computeinfield()
    {
    }


    /**
     * this function finds a solution of the equation bx = b.
     * exception is thrown if the linear equation system has no solution
     *
     * @param b this matrix is the left part of the
     *          equation (b in the equation above)
     * @param b the right part of the equation
     *          (b in the equation above)
     * @return x  the solution of the equation if it is solvable
     *         null otherwise
     * @throws runtimeexception if les is not solvable
     */
    public short[] solveequation(short[][] b, short[] b)
    {
        try
        {

            if (b.length != b.length)
            {
                throw new runtimeexception(
                    "the equation system is not solvable");
            }

            /** initialize **/
            // this matrix stores b and b from the equation b*x = b
            // b is stored as the last column.
            // b contains one column more than rows.
            // in this column we store a free coefficient that should be later subtracted from b
            a = new short[b.length][b.length + 1];
            // stores the solution of the les
            x = new short[b.length];

            /** copy b into the global matrix a **/
            for (int i = 0; i < b.length; i++)
            { // rows
                for (int j = 0; j < b[0].length; j++)
                { // cols
                    a[i][j] = b[i][j];
                }
            }

            /** copy the vector b into the global a **/
            //the free coefficient, stored in the last column of a( a[i][b.length]
            // is to be subtracted from b
            for (int i = 0; i < b.length; i++)
            {
                a[i][b.length] = gf2field.addelem(b[i], a[i][b.length]);
            }

            /** call the methods for gauss elimination and backward substitution **/
            computezerosunder(false);     // obtain zeros under the diagonal
            substitute();

            return x;

        }
        catch (runtimeexception rte)
        {
            return null; // the les is not solvable!
        }
    }

    /**
     * this function computes the inverse of a given matrix using the gauss-
     * elimination method.
     * <p/>
     * an exception is thrown if the matrix has no inverse
     *
     * @param coef the matrix which inverse matrix is needed
     * @return inverse matrix of the input matrix.
     *         if the matrix is singular, null is returned.
     * @throws runtimeexception if the given matrix is not invertible
     */
    public short[][] inverse(short[][] coef)
    {
        try
        {
            /** initialization: **/
            short factor;
            short[][] inverse;
            a = new short[coef.length][2 * coef.length];
            if (coef.length != coef[0].length)
            {
                throw new runtimeexception(
                    "the matrix is not invertible. please choose another one!");
            }

            /** prepare: copy coef and the identity matrix into the global a. **/
            for (int i = 0; i < coef.length; i++)
            {
                for (int j = 0; j < coef.length; j++)
                {
                    //copy the input matrix coef into a
                    a[i][j] = coef[i][j];
                }
                // copy the identity matrix into a.
                for (int j = coef.length; j < 2 * coef.length; j++)
                {
                    a[i][j] = 0;
                }
                a[i][i + a.length] = 1;
            }

            /** elimination operations to get the identity matrix from the left side of a. **/
            // modify a to get 0s under the diagonal.
            computezerosunder(true);

            // modify a to get only 1s on the diagonal: a[i][j] =a[i][j]/a[i][i].
            for (int i = 0; i < a.length; i++)
            {
                factor = gf2field.invelem(a[i][i]);
                for (int j = i; j < 2 * a.length; j++)
                {
                    a[i][j] = gf2field.multelem(a[i][j], factor);
                }
            }

            //modify a to get only 0s above the diagonal.
            computezerosabove();

            // copy the result (the second half of a) in the matrix inverse.
            inverse = new short[a.length][a.length];
            for (int i = 0; i < a.length; i++)
            {
                for (int j = a.length; j < 2 * a.length; j++)
                {
                    inverse[i][j - a.length] = a[i][j];
                }
            }
            return inverse;

        }
        catch (runtimeexception rte)
        {
            // the matrix is not invertible! a new one should be generated!
            return null;
        }
    }

    /**
     * elimination under the diagonal.
     * this function changes a matrix so that it contains only zeros under the
     * diagonal(ai,i) using only gauss-elimination operations.
     * <p/>
     * it is used in solveequaton as well as in the function for
     * finding an inverse of a matrix: {@link}inverse. both of them use the
     * gauss-elimination method.
     * <p/>
     * the result is stored in the global matrix a
     *
     * @param usedforinverse this parameter shows if the function is used by the
     *                       solveequation-function or by the inverse-function and according
     *                       to this creates matrices of different sizes.
     * @throws runtimeexception in case a multiplicative inverse of 0 is needed
     */
    private void computezerosunder(boolean usedforinverse)
        throws runtimeexception
    {

        //the number of columns in the global a where the tmp results are stored
        int length;
        short tmp = 0;

        //the function is used in inverse() - a should have 2 times more columns than rows
        if (usedforinverse)
        {
            length = 2 * a.length;
        }
        //the function is used in solveequation - a has 1 column more than rows
        else
        {
            length = a.length + 1;
        }

        //elimination operations to modify a so that that it contains only 0s under the diagonal
        for (int k = 0; k < a.length - 1; k++)
        { // the fixed row
            for (int i = k + 1; i < a.length; i++)
            { // rows
                short factor1 = a[i][k];
                short factor2 = gf2field.invelem(a[k][k]);

                //the element which multiplicative inverse is needed, is 0
                //in this case is the input matrix not invertible
                if (factor2 == 0)
                {
                    throw new runtimeexception("matrix not invertible! we have to choose another one!");
                }

                for (int j = k; j < length; j++)
                {// columns
                    // tmp=a[k,j] / a[k,k]
                    tmp = gf2field.multelem(a[k][j], factor2);
                    // tmp = a[i,k] * a[k,j] / a[k,k]
                    tmp = gf2field.multelem(factor1, tmp);
                    // a[i,j]=a[i,j]-a[i,k]/a[k,k]*a[k,j];
                    a[i][j] = gf2field.addelem(a[i][j], tmp);
                }
            }
        }
    }

    /**
     * elimination above the diagonal.
     * this function changes a matrix so that it contains only zeros above the
     * diagonal(ai,i) using only gauss-elimination operations.
     * <p/>
     * it is used in the inverse-function
     * the result is stored in the global matrix a
     *
     * @throws runtimeexception in case a multiplicative inverse of 0 is needed
     */
    private void computezerosabove()
        throws runtimeexception
    {
        short tmp = 0;
        for (int k = a.length - 1; k > 0; k--)
        { // the fixed row
            for (int i = k - 1; i >= 0; i--)
            { // rows
                short factor1 = a[i][k];
                short factor2 = gf2field.invelem(a[k][k]);
                if (factor2 == 0)
                {
                    throw new runtimeexception("the matrix is not invertible");
                }
                for (int j = k; j < 2 * a.length; j++)
                { // columns
                    // tmp = a[k,j] / a[k,k]
                    tmp = gf2field.multelem(a[k][j], factor2);
                    // tmp = a[i,k] * a[k,j] / a[k,k]
                    tmp = gf2field.multelem(factor1, tmp);
                    // a[i,j] = a[i,j] - a[i,k] / a[k,k] * a[k,j];
                    a[i][j] = gf2field.addelem(a[i][j], tmp);
                }
            }
        }
    }


    /**
     * this function uses backward substitution to find x
     * of the linear equation system (les) b*x = b,
     * where a a triangle-matrix is (contains only zeros under the diagonal)
     * and b is a vector
     * <p/>
     * if the multiplicative inverse of 0 is needed, an exception is thrown.
     * in this case is the les not solvable
     *
     * @throws runtimeexception in case a multiplicative inverse of 0 is needed
     */
    private void substitute()
        throws runtimeexception
    {

        // for the temporary results of the operations in field
        short tmp, temp;

        temp = gf2field.invelem(a[a.length - 1][a.length - 1]);
        if (temp == 0)
        {
            throw new runtimeexception("the equation system is not solvable");
        }

        /** backward substitution **/
        x[a.length - 1] = gf2field.multelem(a[a.length - 1][a.length], temp);
        for (int i = a.length - 2; i >= 0; i--)
        {
            tmp = a[i][a.length];
            for (int j = a.length - 1; j > i; j--)
            {
                temp = gf2field.multelem(a[i][j], x[j]);
                tmp = gf2field.addelem(tmp, temp);
            }

            temp = gf2field.invelem(a[i][i]);
            if (temp == 0)
            {
                throw new runtimeexception("not solvable equation system");
            }
            x[i] = gf2field.multelem(tmp, temp);
        }
    }


    /**
     * this function multiplies two given matrices.
     * if the given matrices cannot be multiplied due
     * to different sizes, an exception is thrown.
     *
     * @param m1 -the 1st matrix
     * @param m2 -the 2nd matrix
     * @return a = m1*m2
     * @throws runtimeexception in case the given matrices cannot be multiplied
     * due to different dimensions.
     */
    public short[][] multiplymatrix(short[][] m1, short[][] m2)
        throws runtimeexception
    {

        if (m1[0].length != m2.length)
        {
            throw new runtimeexception("multiplication is not possible!");
        }
        short tmp = 0;
        a = new short[m1.length][m2[0].length];
        for (int i = 0; i < m1.length; i++)
        {
            for (int j = 0; j < m2.length; j++)
            {
                for (int k = 0; k < m2[0].length; k++)
                {
                    tmp = gf2field.multelem(m1[i][j], m2[j][k]);
                    a[i][k] = gf2field.addelem(a[i][k], tmp);
                }
            }
        }
        return a;
    }

    /**
     * this function multiplies a given matrix with a one-dimensional array.
     * <p/>
     * an exception is thrown, if the number of columns in the matrix and
     * the number of rows in the one-dim. array differ.
     *
     * @param m1 the matrix to be multiplied
     * @param m  the one-dimensional array to be multiplied
     * @return m1*m
     * @throws runtimeexception in case of dimension inconsistency
     */
    public short[] multiplymatrix(short[][] m1, short[] m)
        throws runtimeexception
    {
        if (m1[0].length != m.length)
        {
            throw new runtimeexception("multiplication is not possible!");
        }
        short tmp = 0;
        short[] b = new short[m1.length];
        for (int i = 0; i < m1.length; i++)
        {
            for (int j = 0; j < m.length; j++)
            {
                tmp = gf2field.multelem(m1[i][j], m[j]);
                b[i] = gf2field.addelem(b[i], tmp);
            }
        }
        return b;
    }

    /**
     * addition of two vectors
     *
     * @param vector1 first summand, always of dim n
     * @param vector2 second summand, always of dim n
     * @return addition of vector1 and vector2
     * @throws runtimeexception in case the addition is impossible
     * due to inconsistency in the dimensions
     */
    public short[] addvect(short[] vector1, short[] vector2)
    {
        if (vector1.length != vector2.length)
        {
            throw new runtimeexception("multiplication is not possible!");
        }
        short rslt[] = new short[vector1.length];
        for (int n = 0; n < rslt.length; n++)
        {
            rslt[n] = gf2field.addelem(vector1[n], vector2[n]);
        }
        return rslt;
    }

    /**
     * multiplication of column vector with row vector
     *
     * @param vector1 column vector, always n x 1
     * @param vector2 row vector, always 1 x n
     * @return resulting n x n matrix of multiplication
     * @throws runtimeexception in case the multiplication is impossible due to
     * inconsistency in the dimensions
     */
    public short[][] multvects(short[] vector1, short[] vector2)
    {
        if (vector1.length != vector2.length)
        {
            throw new runtimeexception("multiplication is not possible!");
        }
        short rslt[][] = new short[vector1.length][vector2.length];
        for (int i = 0; i < vector1.length; i++)
        {
            for (int j = 0; j < vector2.length; j++)
            {
                rslt[i][j] = gf2field.multelem(vector1[i], vector2[j]);
            }
        }
        return rslt;
    }

    /**
     * multiplies vector with scalar
     *
     * @param scalar galois element to multiply vector with
     * @param vector vector to be multiplied
     * @return vector multiplied with scalar
     */
    public short[] multvect(short scalar, short[] vector)
    {
        short rslt[] = new short[vector.length];
        for (int n = 0; n < rslt.length; n++)
        {
            rslt[n] = gf2field.multelem(scalar, vector[n]);
        }
        return rslt;
    }

    /**
     * multiplies matrix with scalar
     *
     * @param scalar galois element to multiply matrix with
     * @param matrix 2-dim n x n matrix to be multiplied
     * @return matrix multiplied with scalar
     */
    public short[][] multmatrix(short scalar, short[][] matrix)
    {
        short[][] rslt = new short[matrix.length][matrix[0].length];
        for (int i = 0; i < matrix.length; i++)
        {
            for (int j = 0; j < matrix[0].length; j++)
            {
                rslt[i][j] = gf2field.multelem(scalar, matrix[i][j]);
            }
        }
        return rslt;
    }

    /**
     * adds the n x n matrices matrix1 and matrix2
     *
     * @param matrix1 first summand
     * @param matrix2 second summand
     * @return addition of matrix1 and matrix2; both having the dimensions n x n
     * @throws runtimeexception in case the addition is not possible because of
     * different dimensions of the matrices
     */
    public short[][] addsquarematrix(short[][] matrix1, short[][] matrix2)
    {
        if (matrix1.length != matrix2.length || matrix1[0].length != matrix2[0].length)
        {
            throw new runtimeexception("addition is not possible!");
        }

        short[][] rslt = new short[matrix1.length][matrix1.length];//
        for (int i = 0; i < matrix1.length; i++)
        {
            for (int j = 0; j < matrix2.length; j++)
            {
                rslt[i][j] = gf2field.addelem(matrix1[i][j], matrix2[i][j]);
            }
        }
        return rslt;
    }

}
