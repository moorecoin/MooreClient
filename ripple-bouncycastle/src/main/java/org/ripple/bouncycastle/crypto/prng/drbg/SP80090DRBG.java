package org.ripple.bouncycastle.crypto.prng.drbg;

/**
 * interface to sp800-90a deterministic random bit generators.
 */
public interface sp80090drbg
{
    /**
     * populate a passed in array with random data.
     *
     * @param output output array for generated bits.
     * @param additionalinput additional input to be added to the drbg in this step.
     * @param predictionresistant true if a reseed should be forced, false otherwise.
     *
     * @return number of bits generated, -1 if a reseed required.
     */
    int generate(byte[] output, byte[] additionalinput, boolean predictionresistant);

    /**
     * reseed the drbg.
     *
     * @param additionalinput additional input to be added to the drbg in this step.
     */
    void reseed(byte[] additionalinput);
}
