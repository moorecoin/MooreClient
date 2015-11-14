package org.ripple.bouncycastle.crypto.tls;

import java.security.securerandom;

public interface tlscontext
{

    securerandom getsecurerandom();

    securityparameters getsecurityparameters();

    boolean isserver();

    protocolversion getclientversion();

    protocolversion getserverversion();

    object getuserobject();

    void setuserobject(object userobject);

    /**
     * export keying material according to rfc 5705: "keying material exporters for tls".
     *
     * @param asciilabel    indicates which application will use the exported keys.
     * @param context_value allows the application using the exporter to mix its own data with the tls prf for
     *                      the exporter output.
     * @param length        the number of bytes to generate
     * @return a pseudorandom bit string of 'length' bytes generated from the master_secret.
     */
    byte[] exportkeyingmaterial(string asciilabel, byte[] context_value, int length);
}
