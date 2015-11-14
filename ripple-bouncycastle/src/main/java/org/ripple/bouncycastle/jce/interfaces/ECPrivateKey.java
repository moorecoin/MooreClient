package org.ripple.bouncycastle.jce.interfaces;

import java.math.biginteger;
import java.security.privatekey;

/**
 * interface for elliptic curve private keys.
 */
public interface ecprivatekey
    extends eckey, privatekey
{
    /**
     * return the private value d.
     */
    public biginteger getd();
}
