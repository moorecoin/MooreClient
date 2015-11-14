package org.ripple.bouncycastle.crypto;

import java.math.biginteger;

/**
 * the basic interface that basic diffie-hellman implementations
 * conforms to.
 */
public interface basicagreement
{
    /**
     * initialise the agreement engine.
     */
    void init(cipherparameters param);

    /**
     * return the field size for the agreement algorithm in bytes.
     */
    int getfieldsize();

    /**
     * given a public key from a given party calculate the next
     * message in the agreement sequence. 
     */
    biginteger calculateagreement(cipherparameters pubkey);
}
