package org.ripple.bouncycastle.openpgp.operator.jcajce;

import java.security.keypair;
import java.security.privatekey;
import java.security.publickey;
import java.util.date;

import org.ripple.bouncycastle.openpgp.pgpexception;
import org.ripple.bouncycastle.openpgp.pgpkeypair;
import org.ripple.bouncycastle.openpgp.pgpprivatekey;
import org.ripple.bouncycastle.openpgp.pgppublickey;

public class jcapgpkeypair
    extends pgpkeypair
{
    private static pgppublickey getpublickey(int algorithm, publickey pubkey, date date)
        throws pgpexception
    {
        return  new jcapgpkeyconverter().getpgppublickey(algorithm, pubkey, date);
    }

    private static pgpprivatekey getprivatekey(pgppublickey pub, privatekey privkey)
        throws pgpexception
    {
        return new jcapgpkeyconverter().getpgpprivatekey(pub, privkey);
    }

    public jcapgpkeypair(int algorithm, keypair keypair, date date)
        throws pgpexception
    {
        this.pub = getpublickey(algorithm, keypair.getpublic(), date);
        this.priv = getprivatekey(this.pub, keypair.getprivate());
    }
}
