package org.ripple.bouncycastle.crypto.commitments;

import java.security.securerandom;

import org.ripple.bouncycastle.crypto.commitment;
import org.ripple.bouncycastle.crypto.committer;
import org.ripple.bouncycastle.crypto.datalengthexception;
import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.crypto.extendeddigest;
import org.ripple.bouncycastle.util.arrays;

/**
 * a basic hash-committer as described in "making mix nets robust for electronic voting by randomized partial checking",
 * by jakobsson, juels, and rivest (11th usenix security symposium, 2002).
 */
public class hashcommitter
    implements committer
{
    private final digest digest;
    private final int bytelength;
    private final securerandom random;

    /**
     * base constructor. the maximum message length that can be committed to is half the length of the internal
     * block size for the digest (extendeddigest.getblocklength()).
     *
     * @param digest digest to use for creating commitments.
     * @param random source of randomness for generating secrets.
     */
    public hashcommitter(extendeddigest digest, securerandom random)
    {
        this.digest = digest;
        this.bytelength = digest.getbytelength();
        this.random = random;
    }

    /**
     * generate a commitment for the passed in message.
     *
     * @param message the message to be committed to,
     * @return a commitment
     */
    public commitment commit(byte[] message)
    {
        if (message.length > bytelength / 2)
        {
            throw new datalengthexception("message to be committed to too large for digest.");
        }

        byte[] w = new byte[bytelength - message.length];

        random.nextbytes(w);

        return new commitment(w, calculatecommitment(w, message));
    }

    /**
     * return true if the passed in commitment represents a commitment to the passed in maessage.
     *
     * @param commitment a commitment previously generated.
     * @param message the message that was expected to have been committed to.
     * @return true if commitment matches message, false otherwise.
     */
    public boolean isrevealed(commitment commitment, byte[] message)
    {
        byte[] calccommitment = calculatecommitment(commitment.getsecret(), message);

        return arrays.constanttimeareequal(commitment.getcommitment(), calccommitment);
    }

    private byte[] calculatecommitment(byte[] w, byte[] message)
    {
        byte[] commitment = new byte[digest.getdigestsize()];

        digest.update(w, 0, w.length);
        digest.update(message, 0, message.length);
        digest.dofinal(commitment, 0);

        return commitment;
    }
}
