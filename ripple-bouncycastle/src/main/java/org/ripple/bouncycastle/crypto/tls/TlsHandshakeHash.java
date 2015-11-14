package org.ripple.bouncycastle.crypto.tls;

import org.ripple.bouncycastle.crypto.digest;

interface tlshandshakehash
    extends digest
{

    void init(tlscontext context);

    tlshandshakehash commit();

    tlshandshakehash fork();
}
