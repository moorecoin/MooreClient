package org.ripple.bouncycastle.jce.spec;

import java.security.privatekey;
import java.security.publickey;
import java.security.spec.keyspec;

import org.ripple.bouncycastle.jce.interfaces.mqvprivatekey;

/**
 * static/ephemeral private key (pair) for use with ecmqv key agreement
 * (optionally provides the ephemeral public key)
 */
public class mqvprivatekeyspec
    implements keyspec, mqvprivatekey
{
    private privatekey staticprivatekey;
    private privatekey ephemeralprivatekey;
    private publickey ephemeralpublickey;

    /**
     * @param staticprivatekey the static private key.
     * @param ephemeralprivatekey the ephemeral private key.
     */
    public mqvprivatekeyspec(
            privatekey  staticprivatekey,
            privatekey  ephemeralprivatekey)
    {
        this(staticprivatekey, ephemeralprivatekey, null);
    }

    /**
     * @param staticprivatekey the static private key.
     * @param ephemeralprivatekey the ephemeral private key.
     * @param ephemeralpublickey the ephemeral public key (may be null).
     */
    public mqvprivatekeyspec(
        privatekey  staticprivatekey,
        privatekey  ephemeralprivatekey,
        publickey   ephemeralpublickey)
    {
        this.staticprivatekey = staticprivatekey;
        this.ephemeralprivatekey = ephemeralprivatekey;
        this.ephemeralpublickey = ephemeralpublickey;
    }

    /**
     * return the static private key
     */
    public privatekey getstaticprivatekey()
    {
        return staticprivatekey;
    }

    /**
     * return the ephemeral private key
     */
    public privatekey getephemeralprivatekey()
    {
        return ephemeralprivatekey;
    }

    /**
     * return the ephemeral public key (may be null)
     */
    public publickey getephemeralpublickey()
    {
        return ephemeralpublickey;
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
