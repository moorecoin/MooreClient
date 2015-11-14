package org.ripple.bouncycastle.pqc.math.linearalgebra;

/**
 * this class describes some operations with matrices over finite field <i>gf(2<sup>m</sup>)</i>
 * with small <i>m</i> (1< m <32).
 *
 * @see matrix
 */
public class gf2mmatrix
    extends matrix
{

    /**
     * finite field gf(2^m)
     */
    protected gf2mfield field;

    /**
     * for the matrix representation the array of type int[][] is used, thus
     * every element of the array keeps one element of the matrix (element from
     * finite field gf(2^m))
     */
    protected int[][] matrix;

    /**
     * constructor.
     *
     * @param field a finite field gf(2^m)
     * @param enc   byte[] matrix in byte array form
     */
    public gf2mmatrix(gf2mfield field, byte[] enc)
    {

        this.field = field;

        // decode matrix
        int d = 8;
        int count = 1;
        while (field.getdegree() > d)
        {
            count++;
            d += 8;
        }

        if (enc.length < 5)
        {
            throw new illegalargumentexception(
                " error: given array is not encoded matrix over gf(2^m)");
        }

        this.numrows = ((enc[3] & 0xff) << 24) ^ ((enc[2] & 0xff) << 16)
            ^ ((enc[1] & 0xff) << 8) ^ (enc[0] & 0xff);

        int n = count * this.numrows;

        if ((this.numrows <= 0) || (((enc.length - 4) % n) != 0))
        {
            throw new illegalargumentexception(
                " error: given array is not encoded matrix over gf(2^m)");
        }

        this.numcolumns = (enc.length - 4) / n;

        matrix = new int[this.numrows][this.numcolumns];
        count = 4;
        for (int i = 0; i < this.numrows; i++)
        {
            for (int j = 0; j < this.numcolumns; j++)
            {
                for (int jj = 0; jj < d; jj += 8)
                {
                    matrix[i][j] ^= (enc[count++] & 0x000000ff) << jj;
                }
                if (!this.field.iselementofthisfield(matrix[i][j]))
                {
                    throw new illegalargumentexception(
                        " error: given array is not encoded matrix over gf(2^m)");
                }
            }
        }
    }

    /**
     * copy constructor.
     *
     * @param other another {@link gf2mmatrix}
     */
    public gf2mmatrix(gf2mmatrix other)
    {
        numrows = other.numrows;
        numcolumns = other.numcolumns;
        field = other.field;
        matrix = new int[numrows][];
        for (int i = 0; i < numrows; i++)
        {
            matrix[i] = intutils.clone(other.matrix[i]);
        }
    }

    /**
     * constructor.
     *
     * @param field  a finite field gf(2^m)
     * @param matrix the matrix as int array. only the reference is copied.
     */
    protected gf2mmatrix(gf2mfield field, int[][] matrix)
    {
        this.field = field;
        this.matrix = matrix;
        numrows = matrix.length;
        numcolumns = matrix[0].length;
    }

    /**
     * @return a byte array encoding of this matrix
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

        byte[] bf = new byte[this.numrows * this.numcolumns * count + 4];
        bf[0] = (byte)(this.numrows & 0xff);
        bf[1] = (byte)((this.numrows >>> 8) & 0xff);
        bf[2] = (byte)((this.numrows >>> 16) & 0xff);
        bf[3] = (byte)((this.numrows >>> 24) & 0xff);

        count = 4;
        for (int i = 0; i < this.numrows; i++)
        {
            for (int j = 0; j < this.numcolumns; j++)
            {
                for (int jj = 0; jj < d; jj += 8)
                {
                    bf[count++] = (byte)(matrix[i][j] >>> jj);
                }
            }
        }

        return bf;
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
            for (int j = 0; j < numcolumns; j++)
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
     * compute the inverse of this matrix.
     *
     * @return the inverse of this matrix (newly created).
     */
    public matrix computeinverse()
    {
        if (numrows != numcolumns)
        {
            throw new arithmeticexception("matrix is not invertible.");
        }

        // clone this matrix
        int[][] tmpmatrix = new int[numrows][numrows];
        for (int i = numrows - 1; i >= 0; i--)
        {
            tmpmatrix[i] = intutils.clone(matrix[i]);
        }

        // initialize inverse matrix as unit matrix
        int[][] invmatrix = new int[numrows][numrows];
        for (int i = numrows - 1; i >= 0; i--)
        {
            invmatrix[i][i] = 1;
        }

        // simultaneously compute gaussian reduction of tmpmatrix and unit
        // matrix
        for (int i = 0; i < numrows; i++)
        {
            // if diagonal element is zero
            if (tmpmatrix[i][i] == 0)
            {
                boolean foundnonzero = false;
                // find a non-zero element in the same column
                for (int j = i + 1; j < numrows; j++)
                {
                    if (tmpmatrix[j][i] != 0)
                    {
                        // found it, swap rows ...
                        foundnonzero = true;
                        swapcolumns(tmpmatrix, i, j);
                        swapcolumns(invmatrix, i, j);
                        // ... and quit searching
                        j = numrows;
                        continue;
                    }
                }
                // if no non-zero element was found
                if (!foundnonzero)
                {
                    // the matrix is not invertible
                    throw new arithmeticexception("matrix is not invertible.");
                }
            }

            // normalize i-th row
            int coef = tmpmatrix[i][i];
            int invcoef = field.inverse(coef);
            multrowwithelementthis(tmpmatrix[i], invcoef);
            multrowwithelementthis(invmatrix[i], invcoef);

            // normalize all other rows
            for (int j = 0; j < numrows; j++)
            {
                if (j != i)
                {
                    coef = tmpmatrix[j][i];
                    if (coef != 0)
                    {
                        int[] tmprow = multrowwithelement(tmpmatrix[i], coef);
                        int[] tmpinvrow = multrowwithelement(invmatrix[i], coef);
                        addtorow(tmprow, tmpmatrix[j]);
                        addtorow(tmpinvrow, invmatrix[j]);
                    }
                }
            }
        }

        return new gf2mmatrix(field, invmatrix);
    }

    private static void swapcolumns(int[][] matrix, int first, int second)
    {
        int[] tmp = matrix[first];
        matrix[first] = matrix[second];
        matrix[second] = tmp;
    }

    private void multrowwithelementthis(int[] row, int element)
    {
        for (int i = row.length - 1; i >= 0; i--)
        {
            row[i] = field.mult(row[i], element);
        }
    }

    private int[] multrowwithelement(int[] row, int element)
    {
        int[] result = new int[row.length];
        for (int i = row.length - 1; i >= 0; i--)
        {
            result[i] = field.mult(row[i], element);
        }
        return result;
    }

    /**
     * add one row to another.
     *
     * @param fromrow the addend
     * @param torow   the row to add to
     */
    private void addtorow(int[] fromrow, int[] torow)
    {
        for (int i = torow.length - 1; i >= 0; i--)
        {
            torow[i] = field.add(fromrow[i], torow[i]);
        }
    }

    public matrix rightmultiply(matrix a)
    {
        throw new runtimeexception("not implemented.");
    }

    public matrix rightmultiply(permutation perm)
    {
        throw new runtimeexception("not implemented.");
    }

    public vector leftmultiply(vector vector)
    {
        throw new runtimeexception("not implemented.");
    }

    public vector rightmultiply(vector vector)
    {
        throw new runtimeexception("not implemented.");
    }

    /**
     * checks if given object is equal to this matrix. the method returns false
     * whenever the given object is not a matrix over gf(2^m).
     *
     * @param other object
     * @return true or false
     */
    public boolean equals(object other)
    {

        if (other == null || !(other instanceof gf2mmatrix))
        {
            return false;
        }

        gf2mmatrix othermatrix = (gf2mmatrix)other;

        if ((!this.field.equals(othermatrix.field))
            || (othermatrix.numrows != this.numcolumns)
            || (othermatrix.numcolumns != this.numcolumns))
        {
            return false;
        }

        for (int i = 0; i < this.numrows; i++)
        {
            for (int j = 0; j < this.numcolumns; j++)
            {
                if (this.matrix[i][j] != othermatrix.matrix[i][j])
                {
                    return false;
                }
            }
        }

        return true;
    }

    public int hashcode()
    {
        int hash = (this.field.hashcode() * 31 + numrows) * 31 + numcolumns;
        for (int i = 0; i < this.numrows; i++)
        {
            for (int j = 0; j < this.numcolumns; j++)
            {
                hash = hash * 31 + matrix[i][j];
            }
        }
        return hash;
    }

    public string tostring()
    {
        string str = this.numrows + " x " + this.numcolumns + " matrix over "
            + this.field.tostring() + ": \n";

        for (int i = 0; i < this.numrows; i++)
        {
            for (int j = 0; j < this.numcolumns; j++)
            {
                str = str + this.field.elementtostr(matrix[i][j]) + " : ";
            }
            str = str + "\n";
        }

        return str;
    }

}
