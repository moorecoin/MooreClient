package org.ripple.bouncycastle.crypto;

/**
 * signer with message recovery.
 */
public interface signerwithrecovery 
    extends signer
{
    /**
     * returns true if the signer has recovered the full message as
     * part of signature verification.
     * 
     * @return true if full message recovered.
     */
    public boolean hasfullmessage();
    
    /**
     * returns a reference to what message was recovered (if any).
     * 
     * @return full/partial message, null if nothing.
     */
    public byte[] getrecoveredmessage();

    /**
     * perform an update with the recovered message before adding any other data. this must
     * be the first update method called, and calling it will result in the signer assuming
     * that further calls to update will include message content past what is recoverable.
     *
     * @param signature the signature that we are in the process of verifying.
     * @throws illegalstateexception
     */
    public void updatewithrecoveredmessage(byte[] signature)
        throws invalidciphertextexception;
}
