package org.ripple.bouncycastle.openpgp.operator.bc;

import java.util.date;

import org.ripple.bouncycastle.crypto.asymmetriccipherkeypair;
import org.ripple.bouncycastle.crypto.params.asymmetrickeyparameter;
import org.ripple.bouncycastle.openpgp.pgpexception;
import org.ripple.bouncycastle.openpgp.pgpkeypair;
import org.ripple.bouncycastle.openpgp.pgpprivatekey;
import org.ripple.bouncycastle.openpgp.pgppublickey;

public class bcpgpkeypair
    extends pgpkeypair
{
    private static pgppublickey getpublickey(int algorithm, asymmetrickeyparameter pubkey, date date)
        throws pgpexception
    {
        return new bcpgpkeyconverter().getpgppublickey(algorithm, pubkey, date);
    }

    private static pgpprivatekey getprivatekey(pgppublickey pub, asymmetrickeyparameter privkey)
        throws pgpexception
    {
        return new bcpgpkeyconverter().getpgpprivatekey(pub, privkey);
    }

    public bcpgpkeypair(int algorithm, asymmetriccipherkeypair keypair, date date)
        throws pgpexception
    {
        this.pub = getpublickey(algorithm, (asymmetrickeyparameter)keypair.getpublic(), date);
        this.priv = getprivatekey(this.pub, (asymmetrickeyparameter)keypair.getprivate());
    }
}
