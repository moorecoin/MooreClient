package org.ripple.bouncycastle.jce.interfaces;

import java.security.publickey;

import org.ripple.bouncycastle.math.ec.ecpoint;

/**
 * interface for elliptic curve public keys.
 */
public interface ecpublickey
    extends eckey, publickey
{
    /**
     * return the public point q
     */
    public ecpoint getq();
}
