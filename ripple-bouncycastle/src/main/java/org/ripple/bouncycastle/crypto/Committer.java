package org.ripple.bouncycastle.crypto;

/**
 * general interface fdr classes that produce and validate commitments.
 */
public interface committer
{
    /**
     * generate a commitment for the passed in message.
     *
     * @param message the message to be committed to,
     * @return a commitment
     */
    commitment commit(byte[] message);

    /**
     * return true if the passed in commitment represents a commitment to the passed in maessage.
     *
     * @param commitment a commitment previously generated.
     * @param message the message that was expected to have been committed to.
     * @return true if commitment matches message, false otherwise.
     */
    boolean isrevealed(commitment commitment, byte[] message);
}
