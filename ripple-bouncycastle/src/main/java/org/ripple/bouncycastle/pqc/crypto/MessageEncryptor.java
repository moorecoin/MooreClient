package org.ripple.bouncycastle.pqc.crypto;


import org.ripple.bouncycastle.crypto.cipherparameters;

public interface messageencryptor
{

    /**
     *
     * @param forencrypting true if we are encrypting a signature, false
     * otherwise.
     * @param param key parameters for encryption or decryption.
     */
    public void init(boolean forencrypting, cipherparameters param);

    /**
     *
     * @param message the message to be signed.
     * @throws exception 
     */
    public byte[] messageencrypt(byte[] message) throws exception;

    /**
     *
     * @param cipher the cipher text of the message
     * @throws exception 
     */
    public byte[] messagedecrypt(byte[] cipher) throws exception;
}
