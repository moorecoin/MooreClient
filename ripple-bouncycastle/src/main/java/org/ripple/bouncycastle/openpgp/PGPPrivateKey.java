package org.ripple.bouncycastle.openpgp;

import java.security.privatekey;
import java.security.interfaces.dsaprivatekey;
import java.security.interfaces.rsaprivatecrtkey;

import org.ripple.bouncycastle.bcpg.bcpgkey;
import org.ripple.bouncycastle.bcpg.dsasecretbcpgkey;
import org.ripple.bouncycastle.bcpg.elgamalsecretbcpgkey;
import org.ripple.bouncycastle.bcpg.publickeypacket;
import org.ripple.bouncycastle.bcpg.rsasecretbcpgkey;
import org.ripple.bouncycastle.jce.interfaces.elgamalprivatekey;
import org.ripple.bouncycastle.openpgp.operator.jcajce.jcapgpkeyconverter;

/**
 * general class to contain a private key for use with other openpgp
 * objects.
 */
public class pgpprivatekey
{
    private long          keyid;
    private privatekey    privatekey;
    private publickeypacket publickeypacket;
    private bcpgkey privatekeydatapacket;

    /**
     * create a pgpprivatekey from a regular private key and the keyid of its associated
     * public key.
     *
     * @param privatekey private key tu use.
     * @param keyid keyid of the corresponding public key.
     * @deprecated use jcapgpkeyconverter
     */
    public pgpprivatekey(
        privatekey        privatekey,
        long              keyid)
    {
        this.privatekey = privatekey;
        this.keyid = keyid;

        if (privatekey instanceof  rsaprivatecrtkey)
        {
            rsaprivatecrtkey rsk = (rsaprivatecrtkey)privatekey;

            privatekeydatapacket = new rsasecretbcpgkey(rsk.getprivateexponent(), rsk.getprimep(), rsk.getprimeq());
        }
        else if (privatekey instanceof dsaprivatekey)
        {
            dsaprivatekey dsk = (dsaprivatekey)privatekey;

            privatekeydatapacket = new dsasecretbcpgkey(dsk.getx());
        }
        else if (privatekey instanceof  elgamalprivatekey)
        {
            elgamalprivatekey esk = (elgamalprivatekey)privatekey;

            privatekeydatapacket = new elgamalsecretbcpgkey(esk.getx());
        }
        else
        {
            throw new illegalargumentexception("unknown key class");
        }

    }

    /**
     * base constructor.
     *
     * create a pgpprivatekey from a keyid and the associated public/private data packets needed
     * to fully describe it.
     *
     * @param keyid keyid associated with the public key.
     * @param publickeypacket the public key data packet to be associated with this private key.
     * @param privatekeydatapacket the private key data packet to be associate with this private key.
     */
    public pgpprivatekey(
        long keyid,
        publickeypacket publickeypacket,
        bcpgkey privatekeydatapacket)
    {
        this.keyid = keyid;
        this.publickeypacket = publickeypacket;
        this.privatekeydatapacket = privatekeydatapacket;
    }

    /**
     * return the keyid associated with the contained private key.
     * 
     * @return long
     */
    public long getkeyid()
    {
        return keyid;
    }
    
    /**
     * return the contained private key.
     * 
     * @return privatekey
     * @deprecated use a jcapgpkeyconverter
     */
    public privatekey getkey()
    {
        if (privatekey != null)
        {
            return privatekey;
        }

        try
        {
            return new jcapgpkeyconverter().setprovider(pgputil.getdefaultprovider()).getprivatekey(this);
        }
        catch (pgpexception e)
        {
            throw new illegalstateexception("unable to convert key: " + e.tostring());
        }
    }

    /**
     * return the public key packet associated with this private key, if available.
     *
     * @return associated public key packet, null otherwise.
     */
    public publickeypacket getpublickeypacket()
    {
        return publickeypacket;
    }

    /**
     * return the private key packet associated with this private key, if available.
     *
     * @return associated private key packet, null otherwise.
     */
    public bcpgkey getprivatekeydatapacket()
    {
        return privatekeydatapacket;
    }
}
