package org.ripple.bouncycastle.crypto.prng;

public interface entropysource
{
    /**
     * return whether or not this entropy source is regarded as prediction resistant.
     *
     * @return true if it is, false otherwise.
     */
    boolean ispredictionresistant();

    /**
     * return a byte array of entropy.
     *
     * @return  entropy bytes.
     */
    byte[] getentropy();

    /**
     * return the number of bits of entropy this source can produce.
     *
     * @return size in bits of the return value of getentropy.
     */
    int entropysize();
}
