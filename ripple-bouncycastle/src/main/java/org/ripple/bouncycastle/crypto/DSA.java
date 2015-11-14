package org.ripple.bouncycastle.crypto;

import java.math.biginteger;

/**
 * interface for classes implementing algorithms modeled similar to the digital signature alorithm.
 */
public interface dsa
{
    /**
     * initialise the signer for signature generation or signature
     * verification.
     *
     * @param forsigning true if we are generating a signature, false
     * otherwise.
     * @param param key parameters for signature generation.
     */
    public void init(boolean forsigning, cipherparameters param);

    /**
     * sign the passed in message (usually the output of a hash function).
     *
     * @param message the message to be signed.
     * @return two big integers representing the r and s values respectively.
     */
    public biginteger[] generatesignature(byte[] message);

    /**
     * verify the message message against the signature values r and s.
     *
     * @param message the message that was supposed to have been signed.
     * @param r the r signature value.
     * @param s the s signature value.
     */
    public boolean verifysignature(byte[] message, biginteger  r, biginteger s);
}
