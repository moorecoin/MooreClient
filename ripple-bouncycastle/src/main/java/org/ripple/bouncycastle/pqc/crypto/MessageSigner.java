package org.ripple.bouncycastle.pqc.crypto;

import org.ripple.bouncycastle.crypto.cipherparameters;

public interface messagesigner
{
    /**
     * initialise the signer for signature generation or signature
     * verification.
     *
     * @param forsigning true if we are generating a signature, false
     *                   otherwise.
     * @param param      key parameters for signature generation.
     */
    public void init(boolean forsigning, cipherparameters param);

    /**
     * sign the passed in message (usually the output of a hash function).
     *
     * @param message the message to be signed.
     * @return the signature of the message
     */
    public byte[] generatesignature(byte[] message);

    /**
     * verify the message message against the signature values r and s.
     *
     * @param message the message that was supposed to have been signed.
     * @param signature the signature of the message
     */
    public boolean verifysignature(byte[] message, byte[] signature);
}
