package org.ripple.bouncycastle.pqc.math.linearalgebra;


/**
 * this abstract class implements an element of the finite field <i>gf(2)<sup>n
 * </sup></i> in either <i>optimal normal basis</i> representation (<i>onb</i>)
 * or in <i>polynomial</i> representation. it is extended by the classes <a
 * href = gf2nonbelement.html><tt> gf2nonbelement</tt></a> and <a href =
 * gf2npolynomialelement.html> <tt>gf2npolynomialelement</tt> </a>.
 *
 * @see gf2npolynomialelement
 * @see gf2nonbelement
 * @see gf2nonbfield
 */
public abstract class gf2nelement
    implements gfelement
{

    // /////////////////////////////////////////////////////////////////////
    // member variables
    // /////////////////////////////////////////////////////////////////////

    /**
     * holds a pointer to this element's corresponding field.
     */
    protected gf2nfield mfield;

    /**
     * holds the extension degree <i>n</i> of this element's corresponding
     * field.
     */
    protected int mdegree;

    // /////////////////////////////////////////////////////////////////////
    // pseudo-constructors
    // /////////////////////////////////////////////////////////////////////

    /**
     * @return a copy of this gf2nelement
     */
    public abstract object clone();

    // /////////////////////////////////////////////////////////////////////
    // assignments
    // /////////////////////////////////////////////////////////////////////

    /**
     * assign the value 0 to this element.
     */
    abstract void assignzero();

    /**
     * assigns the value 1 to this element.
     */
    abstract void assignone();

    // /////////////////////////////////////////////////////////////////////
    // access
    // /////////////////////////////////////////////////////////////////////

    /**
     * returns whether the rightmost bit of the bit representation is set. this
     * is needed for data conversion according to 1363.
     *
     * @return true if the rightmost bit of this element is set
     */
    public abstract boolean testrightmostbit();

    /**
     * checks whether the indexed bit of the bit representation is set
     *
     * @param index the index of the bit to test
     * @return <tt>true</tt> if the indexed bit is set
     */
    abstract boolean testbit(int index);

    /**
     * returns the field of this element.
     *
     * @return the field of this element
     */
    public final gf2nfield getfield()
    {
        return mfield;
    }

    // /////////////////////////////////////////////////////////////////////
    // arithmetic
    // /////////////////////////////////////////////////////////////////////

    /**
     * returns <tt>this</tt> element + 1.
     *
     * @return <tt>this</tt> + 1
     */
    public abstract gf2nelement increase();

    /**
     * increases this element by one.
     */
    public abstract void increasethis();

    /**
     * compute the difference of this element and <tt>minuend</tt>.
     *
     * @param minuend the minuend
     * @return <tt>this - minuend</tt> (newly created)
     * @throws differentfieldsexception if the elements are of different fields.
     */
    public final gfelement subtract(gfelement minuend)
        throws runtimeexception
    {
        return add(minuend);
    }

    /**
     * compute the difference of this element and <tt>minuend</tt>,
     * overwriting this element.
     *
     * @param minuend the minuend
     * @throws differentfieldsexception if the elements are of different fields.
     */
    public final void subtractfromthis(gfelement minuend)
    {
        addtothis(minuend);
    }

    /**
     * returns <tt>this</tt> element to the power of 2.
     *
     * @return <tt>this</tt><sup>2</sup>
     */
    public abstract gf2nelement square();

    /**
     * squares <tt>this</tt> element.
     */
    public abstract void squarethis();

    /**
     * compute the square root of this element and return the result in a new
     * {@link gf2nelement}.
     *
     * @return <tt>this<sup>1/2</sup></tt> (newly created)
     */
    public abstract gf2nelement squareroot();

    /**
     * compute the square root of this element.
     */
    public abstract void squarerootthis();

    /**
     * performs a basis transformation of this element to the given gf2nfield
     * <tt>basis</tt>.
     *
     * @param basis the gf2nfield representation to transform this element to
     * @return this element in the representation of <tt>basis</tt>
     * @throws differentfieldsexception if <tt>this</tt> cannot be converted according to
     * <tt>basis</tt>.
     */
    public final gf2nelement convert(gf2nfield basis)
        throws runtimeexception
    {
        return mfield.convert(this, basis);
    }

    /**
     * returns the trace of this element.
     *
     * @return the trace of this element
     */
    public abstract int trace();

    /**
     * solves a quadratic equation.<br>
     * let z<sup>2</sup> + z = <tt>this</tt>. then this method returns z.
     *
     * @return z with z<sup>2</sup> + z = <tt>this</tt>
     * @throws nosolutionexception if z<sup>2</sup> + z = <tt>this</tt> does not have a
     * solution
     */
    public abstract gf2nelement solvequadraticequation()
        throws runtimeexception;

}
