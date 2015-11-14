package org.ripple.bouncycastle.openpgp;

import java.security.keypair;
import java.security.nosuchproviderexception;
import java.security.privatekey;
import java.security.publickey;
import java.security.interfaces.dsaprivatekey;
import java.security.interfaces.rsaprivatecrtkey;
import java.util.date;

import org.ripple.bouncycastle.bcpg.bcpgkey;
import org.ripple.bouncycastle.bcpg.dsasecretbcpgkey;
import org.ripple.bouncycastle.bcpg.elgamalsecretbcpgkey;
import org.ripple.bouncycastle.bcpg.rsasecretbcpgkey;
import org.ripple.bouncycastle.jce.interfaces.elgamalprivatekey;


/**
 * general class to handle jca key pairs and convert them into openpgp ones.
 * <p>
 * a word for the unwary, the keyid for a openpgp public key is calculated from
 * a hash that includes the time of creation, if you pass a different date to the 
 * constructor below with the same public private key pair the keyid will not be the
 * same as for previous generations of the key, so ideally you only want to do 
 * this once.
 */
public class pgpkeypair
{
    protected pgppublickey        pub;
    protected pgpprivatekey       priv;

    /**
     * @deprecated use bcpgpkeypair or jcapgpkeypair as appropriate.
     */
    public pgpkeypair(
        int             algorithm,
        keypair         keypair,
        date            time,
        string          provider)
        throws pgpexception, nosuchproviderexception
    {
        this(algorithm, keypair.getpublic(), keypair.getprivate(), time, provider);
    }

    /**
     * @deprecated use bcpgpkeypair or jcapgpkeypair as appropriate.
     */
    public pgpkeypair(
        int             algorithm,
        keypair         keypair,
        date            time)
        throws pgpexception
    {
        this(algorithm, keypair.getpublic(), keypair.getprivate(), time);
    }

    /**
     * @deprecated use bcpgpkeypair or jcapgpkeypair as appropriate.
     */
    public pgpkeypair(
        int             algorithm,
        publickey       pubkey,
        privatekey      privkey,
        date            time,
        string          provider)
        throws pgpexception, nosuchproviderexception
    {
        this(algorithm, pubkey, privkey, time);
    }

    /**
     * @deprecated use bcpgpkeypair or jcapgpkeypair as appropriate.
     */
    public pgpkeypair(
        int             algorithm,
        publickey       pubkey,
        privatekey      privkey,
        date            time)
        throws pgpexception
    {
        this.pub = new pgppublickey(algorithm, pubkey, time);

        bcpgkey privpk;

        switch (pub.getalgorithm())
        {
        case pgppublickey.rsa_encrypt:
        case pgppublickey.rsa_sign:
        case pgppublickey.rsa_general:
            rsaprivatecrtkey rsk = (rsaprivatecrtkey)privkey;

            privpk = new rsasecretbcpgkey(rsk.getprivateexponent(), rsk.getprimep(), rsk.getprimeq());
            break;
        case pgppublickey.dsa:
            dsaprivatekey dsk = (dsaprivatekey)privkey;

            privpk = new dsasecretbcpgkey(dsk.getx());
            break;
        case pgppublickey.elgamal_encrypt:
        case pgppublickey.elgamal_general:
            elgamalprivatekey esk = (elgamalprivatekey)privkey;

            privpk = new elgamalsecretbcpgkey(esk.getx());
            break;
        default:
            throw new pgpexception("unknown key class");
        }
        this.priv = new pgpprivatekey(pub.getkeyid(), pub.getpublickeypacket(), privpk);
    }

    /**
     * create a key pair from a pgpprivatekey and a pgppublickey.
     * 
     * @param pub the public key
     * @param priv the private key
     */
    public pgpkeypair(
        pgppublickey    pub,
        pgpprivatekey   priv)
    {
        this.pub = pub;
        this.priv = priv;
    }

    protected pgpkeypair()
    {
    }

    /**
     * return the keyid associated with this key pair.
     * 
     * @return keyid
     */
    public long getkeyid()
    {
        return pub.getkeyid();
    }
    
    public pgppublickey getpublickey()
    {
        return pub;
    }
    
    public pgpprivatekey getprivatekey()
    {
        return priv;
    }
}
