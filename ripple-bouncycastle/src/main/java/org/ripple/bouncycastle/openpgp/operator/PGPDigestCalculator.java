package org.ripple.bouncycastle.openpgp.operator;

import java.io.outputstream;

public interface pgpdigestcalculator
{
    /**
        * return the algorithm number representing the digest implemented by
        * this calculator.
        *
        * @return algorithm number
        */
    int getalgorithm();

    /**
        * returns a stream that will accept data for the purpose of calculating
        * a digest. use org.bouncycastle.util.io.teeoutputstream if you want to accumulate
        * the data on the fly as well.
        *
        * @return an outputstream
        */
    outputstream getoutputstream();

    /**
         * return the digest calculated on what has been written to the calculator's output stream.
         *
         * @return a digest.
         */
    byte[] getdigest();

    /**
     * reset the underlying digest calculator
     */
    void reset();
}
