package org.ripple.bouncycastle.pqc.math.linearalgebra;

import java.math.biginteger;


/**
 * this interface defines a finite field element. it is implemented by the
 * classes {@link gfpelement} and {@link gf2nelement}.
 *
 * @see gfpelement
 * @see gf2nelement
 */
public interface gfelement
{

    /**
     * @return a copy of this gfelement
     */
    object clone();

    // /////////////////////////////////////////////////////////////////
    // comparison
    // /////////////////////////////////////////////////////////////////

    /**
     * compare this curve with another object.
     *
     * @param other the other object
     * @return the result of the comparison
     */
    boolean equals(object other);

    /**
     * @return the hash code of this element
     */
    int hashcode();

    /**
     * checks whether this element is zero.
     *
     * @return <tt>true</tt> if <tt>this</tt> is the zero element
     */
    boolean iszero();

    /**
     * checks whether this element is one.
     *
     * @return <tt>true</tt> if <tt>this</tt> is the one element
     */
    boolean isone();

    // /////////////////////////////////////////////////////////////////////
    // arithmetic
    // /////////////////////////////////////////////////////////////////////

    /**
     * compute the sum of this element and the addend.
     *
     * @param addend the addend
     * @return <tt>this + other</tt> (newly created)
     * @throws differentfieldsexception if the elements are of different fields.
     */
    gfelement add(gfelement addend)
        throws runtimeexception;

    /**
     * compute the sum of this element and the addend, overwriting this element.
     *
     * @param addend the addend
     * @throws differentfieldsexception if the elements are of different fields.
     */
    void addtothis(gfelement addend)
        throws runtimeexception;

    /**
     * compute the difference of this element and <tt>minuend</tt>.
     *
     * @param minuend the minuend
     * @return <tt>this - minuend</tt> (newly created)
     * @throws differentfieldsexception if the elements are of different fields.
     */
    gfelement subtract(gfelement minuend)
        throws runtimeexception;

    /**
     * compute the difference of this element and <tt>minuend</tt>,
     * overwriting this element.
     *
     * @param minuend the minuend
     * @throws differentfieldsexception if the elements are of different fields.
     */
    void subtractfromthis(gfelement minuend);

    /**
     * compute the product of this element and <tt>factor</tt>.
     *
     * @param factor the factor
     * @return <tt>this * factor</tt> (newly created)
     * @throws differentfieldsexception if the elements are of different fields.
     */
    gfelement multiply(gfelement factor)
        throws runtimeexception;

    /**
     * compute <tt>this * factor</tt> (overwrite <tt>this</tt>).
     *
     * @param factor the factor
     * @throws differentfieldsexception if the elements are of different fields.
     */
    void multiplythisby(gfelement factor)
        throws runtimeexception;

    /**
     * compute the multiplicative inverse of this element.
     *
     * @return <tt>this<sup>-1</sup></tt> (newly created)
     * @throws arithmeticexception if <tt>this</tt> is the zero element.
     */
    gfelement invert()
        throws arithmeticexception;

    // /////////////////////////////////////////////////////////////////////
    // conversion
    // /////////////////////////////////////////////////////////////////////

    /**
     * returns this element as flexibigint. the conversion is <a
     * href="http://grouper.ieee.org/groups/1363/">p1363</a>-conform.
     *
     * @return this element as bigint
     */
    biginteger toflexibigint();

    /**
     * returns this element as byte array. the conversion is <a href =
     * "http://grouper.ieee.org/groups/1363/">p1363</a>-conform.
     *
     * @return this element as byte array
     */
    byte[] tobytearray();

    /**
     * return a string representation of this element.
     *
     * @return string representation of this element
     */
    string tostring();

    /**
     * return a string representation of this element. <tt>radix</tt>
     * specifies the radix of the string representation.
     *
     * @param radix specifies the radix of the string representation
     * @return string representation of this element with the specified radix
     */
    string tostring(int radix);

}
