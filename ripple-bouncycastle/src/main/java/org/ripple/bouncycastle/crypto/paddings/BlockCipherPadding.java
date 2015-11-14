package org.ripple.bouncycastle.crypto.paddings;

import java.security.securerandom;

import org.ripple.bouncycastle.crypto.invalidciphertextexception;

/**
 * block cipher padders are expected to conform to this interface
 */
public interface blockcipherpadding
{
    /**
     * initialise the padder.
     *
     * @param random the source of randomness for the padding, if required.
     */
    public void init(securerandom random)
        throws illegalargumentexception;

    /**
     * return the name of the algorithm the cipher implements.
     *
     * @return the name of the algorithm the cipher implements.
     */
    public string getpaddingname();

    /**
     * add the pad bytes to the passed in block, returning the
     * number of bytes added.
     * <p>
     * note: this assumes that the last block of plain text is always 
     * passed to it inside in. i.e. if inoff is zero, indicating the
     * entire block is to be overwritten with padding the value of in
     * should be the same as the last block of plain text. the reason
     * for this is that some modes such as "trailing bit compliment"
     * base the padding on the last byte of plain text.
     * </p>
     */
    public int addpadding(byte[] in, int inoff);

    /**
     * return the number of pad bytes present in the block.
     * @exception invalidciphertextexception if the padding is badly formed
     * or invalid.
     */
    public int padcount(byte[] in)
        throws invalidciphertextexception;
}
