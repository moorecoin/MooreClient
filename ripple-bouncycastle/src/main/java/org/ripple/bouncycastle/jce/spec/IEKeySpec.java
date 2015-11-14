package org.ripple.bouncycastle.jce.spec;

import java.security.privatekey;
import java.security.publickey;
import java.security.spec.keyspec;

import org.ripple.bouncycastle.jce.interfaces.ieskey;

/**
 * key pair for use with an integrated encryptor - together
 * they provide what's required to generate the message.
 */
public class iekeyspec
    implements keyspec, ieskey
{
    private publickey   pubkey;
    private privatekey  privkey;

    /**
     * @param privkey our private key.
     * @param pubkey the public key of the sender/recipient.
     */
    public iekeyspec(
        privatekey  privkey,
        publickey   pubkey)
    {
        this.privkey = privkey;
        this.pubkey = pubkey;
    }

    /**
     * return the intended recipient's/sender's public key.
     */
    public publickey getpublic()
    {
        return pubkey;
    }

    /**
     * return the local private key.
     */
    public privatekey getprivate()
    {
        return privkey;
    }

    /**
     * return "ies"
     */
    public string getalgorithm()
    {
        return "ies";
    }

    /**
     * return null
     */
    public string getformat()
    {
        return null;
    }

    /**
     * returns null
     */
    public byte[] getencoded()
    {
        return null;
    }
}
