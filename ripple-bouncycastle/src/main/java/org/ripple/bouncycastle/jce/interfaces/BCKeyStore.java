package org.ripple.bouncycastle.jce.interfaces;

import java.security.securerandom;

/**
 * all bc provider keystores implement this interface.
 */
public interface bckeystore
{
    /**
     * set the random source for the key store
     */
    public void setrandom(securerandom random);
}
