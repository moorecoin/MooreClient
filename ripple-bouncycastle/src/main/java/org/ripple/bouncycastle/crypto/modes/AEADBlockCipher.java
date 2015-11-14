package org.ripple.bouncycastle.crypto.modes;

import org.ripple.bouncycastle.crypto.blockcipher;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.datalengthexception;
import org.ripple.bouncycastle.crypto.invalidciphertextexception;

/**
 * a block cipher mode that includes authenticated encryption with a streaming mode and optional associated data.
 * @see org.ripple.bouncycastle.crypto.params.aeadparameters
 */
public interface aeadblockcipher
{
    /**
     * initialise the underlying cipher. parameter can either be an aeadparameters or a parameterswithiv object.
     *
     * @param forencryption true if we are setting up for encryption, false otherwise.
     * @param params the necessary parameters for the underlying cipher to be initialised.
     * @exception illegalargumentexception if the params argument is inappropriate.
     */
    public void init(boolean forencryption, cipherparameters params)
        throws illegalargumentexception;

    /**
     * return the name of the algorithm.
     * 
     * @return the algorithm name.
     */
    public string getalgorithmname();

    /**
     * return the cipher this object wraps.
     *
     * @return the cipher this object wraps.
     */
    public blockcipher getunderlyingcipher();

    /**
     * add a single byte to the associated data check.
     * <br>if the implementation supports it, this will be an online operation and will not retain the associated data.
     *
     * @param in the byte to be processed.
     */
    public void processaadbyte(byte in);

    /**
     * add a sequence of bytes to the associated data check.
     * <br>if the implementation supports it, this will be an online operation and will not retain the associated data.
     *
     * @param in the input byte array.
     * @param inoff the offset into the in array where the data to be processed starts.
     * @param len the number of bytes to be processed.
     */
    public void processaadbytes(byte[] in, int inoff, int len);

    /**
     * encrypt/decrypt a single byte.
     *
     * @param in the byte to be processed.
     * @param out the output buffer the processed byte goes into.
     * @param outoff the offset into the output byte array the processed data starts at.
     * @return the number of bytes written to out.
     * @exception datalengthexception if the output buffer is too small.
     */
    public int processbyte(byte in, byte[] out, int outoff)
        throws datalengthexception;

    /**
     * process a block of bytes from in putting the result into out.
     *
     * @param in the input byte array.
     * @param inoff the offset into the in array where the data to be processed starts.
     * @param len the number of bytes to be processed.
     * @param out the output buffer the processed bytes go into.
     * @param outoff the offset into the output byte array the processed data starts at.
     * @return the number of bytes written to out.
     * @exception datalengthexception if the output buffer is too small.
     */
    public int processbytes(byte[] in, int inoff, int len, byte[] out, int outoff)
        throws datalengthexception;

    /**
     * finish the operation either appending or verifying the mac at the end of the data.
     *
     * @param out space for any resulting output data.
     * @param outoff offset into out to start copying the data at.
     * @return number of bytes written into out.
     * @throws illegalstateexception if the cipher is in an inappropriate state.
     * @throws org.ripple.bouncycastle.crypto.invalidciphertextexception if the mac fails to match.
     */
    public int dofinal(byte[] out, int outoff)
        throws illegalstateexception, invalidciphertextexception;

    /**
     * return the value of the mac associated with the last stream processed.
     *
     * @return mac for plaintext data.
     */
    public byte[] getmac();

    /**
     * return the size of the output buffer required for a processbytes
     * an input of len bytes.
     *
     * @param len the length of the input.
     * @return the space required to accommodate a call to processbytes
     * with len bytes of input.
     */
    public int getupdateoutputsize(int len);

    /**
     * return the size of the output buffer required for a processbytes plus a
     * dofinal with an input of len bytes.
     *
     * @param len the length of the input.
     * @return the space required to accommodate a call to processbytes and dofinal
     * with len bytes of input.
     */
    public int getoutputsize(int len);

    /**
     * reset the cipher. after resetting the cipher is in the same state
     * as it was after the last init (if there was one).
     */
    public void reset();
}
