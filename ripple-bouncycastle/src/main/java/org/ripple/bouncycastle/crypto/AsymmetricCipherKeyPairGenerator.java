package org.ripple.bouncycastle.crypto;

/**
 * interface that a public/private key pair generator should conform to.
 */
public interface asymmetriccipherkeypairgenerator
{
    /**
     * intialise the key pair generator.
     *
     * @param param the parameters the key pair is to be initialised with.
     */
    public void init(keygenerationparameters param);

    /**
     * return an asymmetriccipherkeypair containing the generated keys.
     *
     * @return an asymmetriccipherkeypair containing the generated keys.
     */
    public asymmetriccipherkeypair generatekeypair();
}

