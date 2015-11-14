package org.ripple.bouncycastle.jce.spec;

import java.security.publickey;
import java.security.spec.keyspec;

import org.ripple.bouncycastle.jce.interfaces.mqvpublickey;

/**
 * static/ephemeral public key pair for use with ecmqv key agreement
 */
public class mqvpublickeyspec
    implements keyspec, mqvpublickey
{
    private publickey statickey;
    private publickey ephemeralkey;

    /**
     * @param statickey the static public key.
     * @param ephemeralkey the ephemeral public key.
     */
    public mqvpublickeyspec(
        publickey statickey,
        publickey ephemeralkey)
    {
        this.statickey = statickey;
        this.ephemeralkey = ephemeralkey;
    }

    /**
     * return the static public key
     */
    public publickey getstatickey()
    {
        return statickey;
    }
    
    /**
     * return the ephemeral public key
     */
    public publickey getephemeralkey()
    {
        return ephemeralkey;
    }

    /**
     * return "ecmqv"
     */
    public string getalgorithm()
    {
        return "ecmqv";
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
