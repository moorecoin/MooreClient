package org.ripple.bouncycastle.openpgp.operator.jcajce;

import java.security.privatekey;

import org.ripple.bouncycastle.openpgp.pgpprivatekey;
import org.ripple.bouncycastle.openpgp.pgppublickey;

/**
 * a jca privatekey carrier. use this one if you're dealing with a hardware adapter.
 */
public class jcapgpprivatekey
    extends pgpprivatekey
{
    private final privatekey privatekey;

    public jcapgpprivatekey(long keyid, privatekey privatekey)
    {
        super(keyid, null, null);

        this.privatekey = privatekey;
    }

    public jcapgpprivatekey(pgppublickey pubkey, privatekey privatekey)
    {
        super(pubkey.getkeyid(), pubkey.getpublickeypacket(), null);

        this.privatekey = privatekey;
    }

    public privatekey getprivatekey()
    {
        return privatekey;
    }
}
