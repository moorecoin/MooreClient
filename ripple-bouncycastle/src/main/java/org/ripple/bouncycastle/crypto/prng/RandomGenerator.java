package org.ripple.bouncycastle.crypto.prng;

/**
 * generic interface for objects generating random bytes.
 */
public interface randomgenerator
{
    /**
     * add more seed material to the generator.
     *
     * @param seed a byte array to be mixed into the generator's state.
     */
    void addseedmaterial(byte[] seed);

    /**
     * add more seed material to the generator.
     *
     * @param seed a long value to be mixed into the generator's state.
     */
    void addseedmaterial(long seed);

    /**
     * fill bytes with random values.
     *
     * @param bytes byte array to be filled.
     */
    void nextbytes(byte[] bytes);

    /**
     * fill part of bytes with random values.
     *
     * @param bytes byte array to be filled.
     * @param start index to start filling at.
     * @param len length of segment to fill.
     */
    void nextbytes(byte[] bytes, int start, int len);

}
