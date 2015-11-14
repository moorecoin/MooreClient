package org.ripple.bouncycastle.crypto;

/**
 * general holding class for a commitment.
 */
public class commitment
{
    private final byte[] secret;
    private final byte[] commitment;

    /**
     * base constructor.
     *
     * @param secret  an encoding of the secret required to reveal the commitment.
     * @param commitment  an encoding of the sealed commitment.
     */
    public commitment(byte[] secret, byte[] commitment)
    {
        this.secret = secret;
        this.commitment = commitment;
    }

    /**
     * the secret required to reveal the commitment.
     *
     * @return an encoding of the secret associated with the commitment.
     */
    public byte[] getsecret()
    {
        return secret;
    }

    /**
     * the sealed commitment.
     *
     * @return an encoding of the sealed commitment.
     */
    public byte[] getcommitment()
    {
        return commitment;
    }
}
