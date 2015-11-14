package org.ripple.bouncycastle.openpgp;

import java.io.bytearrayinputstream;
import java.io.bytearrayoutputstream;
import java.io.ioexception;
import java.io.inputstream;
import java.io.outputstream;
import java.security.nosuchproviderexception;
import java.security.provider;
import java.security.securerandom;
import java.util.arraylist;
import java.util.collections;
import java.util.iterator;
import java.util.list;

import org.ripple.bouncycastle.bcpg.bcpginputstream;
import org.ripple.bouncycastle.bcpg.packettags;
import org.ripple.bouncycastle.bcpg.publicsubkeypacket;
import org.ripple.bouncycastle.bcpg.secretkeypacket;
import org.ripple.bouncycastle.bcpg.secretsubkeypacket;
import org.ripple.bouncycastle.bcpg.trustpacket;
import org.ripple.bouncycastle.openpgp.operator.keyfingerprintcalculator;
import org.ripple.bouncycastle.openpgp.operator.pbesecretkeydecryptor;
import org.ripple.bouncycastle.openpgp.operator.pbesecretkeyencryptor;
import org.ripple.bouncycastle.openpgp.operator.jcajce.jcakeyfingerprintcalculator;

/**
 * class to hold a single master secret key and its subkeys.
 * <p>
 * often pgp keyring files consist of multiple master keys, if you are trying to process
 * or construct one of these you should use the pgpsecretkeyringcollection class.
 */
public class pgpsecretkeyring
    extends pgpkeyring
{    
    list keys;
    list extrapubkeys;

    pgpsecretkeyring(list keys)
    {
        this(keys, new arraylist());
    }

    private pgpsecretkeyring(list keys, list extrapubkeys)
    {
        this.keys = keys;
        this.extrapubkeys = extrapubkeys;
    }

    /**
     * @deprecated use version that takes keyfingerprintcalculator
     */
    public pgpsecretkeyring(
        byte[]    encoding)
        throws ioexception, pgpexception
    {
        this(new bytearrayinputstream(encoding));
    }

    public pgpsecretkeyring(
        byte[]    encoding,
        keyfingerprintcalculator fingerprintcalculator)
        throws ioexception, pgpexception
    {
        this(new bytearrayinputstream(encoding), fingerprintcalculator);
    }

    /**
     * @deprecated use version that takes keyfingerprintcalculator
     */
    public pgpsecretkeyring(
        inputstream    in)
        throws ioexception, pgpexception
    {
        this(in, new jcakeyfingerprintcalculator());
    }

    public pgpsecretkeyring(
        inputstream              in,
        keyfingerprintcalculator fingerprintcalculator)
        throws ioexception, pgpexception
    {
        this.keys = new arraylist();
        this.extrapubkeys = new arraylist();

        bcpginputstream pin = wrap(in);

        int initialtag = pin.nextpackettag();
        if (initialtag != packettags.secret_key && initialtag != packettags.secret_subkey)
        {
            throw new ioexception(
                "secret key ring doesn't start with secret key tag: " +
                "tag 0x" + integer.tohexstring(initialtag));
        }

        secretkeypacket secret = (secretkeypacket)pin.readpacket();

        //
        // ignore gpg comment packets if found.
        //
        while (pin.nextpackettag() == packettags.experimental_2)
        {
            pin.readpacket();
        }
        
        trustpacket trust = readoptionaltrustpacket(pin);

        // revocation and direct signatures
        list keysigs = readsignaturesandtrust(pin);

        list ids = new arraylist();
        list idtrusts = new arraylist();
        list idsigs = new arraylist();
        readuserids(pin, ids, idtrusts, idsigs);

        keys.add(new pgpsecretkey(secret, new pgppublickey(secret.getpublickeypacket(), trust, keysigs, ids, idtrusts, idsigs, fingerprintcalculator)));


        // read subkeys
        while (pin.nextpackettag() == packettags.secret_subkey
            || pin.nextpackettag() == packettags.public_subkey)
        {
            if (pin.nextpackettag() == packettags.secret_subkey)
            {
                secretsubkeypacket    sub = (secretsubkeypacket)pin.readpacket();

                //
                // ignore gpg comment packets if found.
                //
                while (pin.nextpackettag() == packettags.experimental_2)
                {
                    pin.readpacket();
                }

                trustpacket subtrust = readoptionaltrustpacket(pin);
                list        siglist = readsignaturesandtrust(pin);

                keys.add(new pgpsecretkey(sub, new pgppublickey(sub.getpublickeypacket(), subtrust, siglist, fingerprintcalculator)));
            }
            else
            {
                publicsubkeypacket sub = (publicsubkeypacket)pin.readpacket();

                trustpacket subtrust = readoptionaltrustpacket(pin);
                list        siglist = readsignaturesandtrust(pin);

                extrapubkeys.add(new pgppublickey(sub, subtrust, siglist, fingerprintcalculator));
            }
        }
    }

    /**
     * return the public key for the master key.
     * 
     * @return pgppublickey
     */
    public pgppublickey getpublickey()
    {
        return ((pgpsecretkey)keys.get(0)).getpublickey();
    }

  /**
     * return the public key referred to by the passed in keyid if it
     * is present.
     *
     * @param keyid
     * @return pgppublickey
     */
    public pgppublickey getpublickey(
        long        keyid)
    {
        pgpsecretkey key = getsecretkey(keyid);
        if (key != null)
        {
            return key.getpublickey();
        }

        for (int i = 0; i != extrapubkeys.size(); i++)
        {
            pgppublickey    k = (pgppublickey)keys.get(i);

            if (keyid == k.getkeyid())
            {
                return k;
            }
        }

        return null;
    }

    /**
     * return an iterator containing all the public keys.
     *
     * @return iterator
     */
    public iterator getpublickeys()
    {
        list pubkeys = new arraylist();

        for (iterator it = getsecretkeys(); it.hasnext();)
        {
            pubkeys.add(((pgpsecretkey)it.next()).getpublickey());
        }

        pubkeys.addall(extrapubkeys);

        return collections.unmodifiablelist(pubkeys).iterator();
    }

    /**
     * return the master private key.
     * 
     * @return pgpsecretkey
     */
    public pgpsecretkey getsecretkey()
    {
        return ((pgpsecretkey)keys.get(0));
    }
    
    /**
     * return an iterator containing all the secret keys.
     * 
     * @return iterator
     */
    public iterator getsecretkeys()
    {
        return collections.unmodifiablelist(keys).iterator();
    }
    
    public pgpsecretkey getsecretkey(
        long        keyid)
    {    
        for (int i = 0; i != keys.size(); i++)
        {
            pgpsecretkey    k = (pgpsecretkey)keys.get(i);
            
            if (keyid == k.getkeyid())
            {
                return k;
            }
        }
    
        return null;
    }

    /**
     * return an iterator of the public keys in the secret key ring that
     * have no matching private key. at the moment only personal certificate data
     * appears in this fashion.
     *
     * @return  iterator of unattached, or extra, public keys.
     */
    public iterator getextrapublickeys()
    {
        return extrapubkeys.iterator();
    }

    public byte[] getencoded() 
        throws ioexception
    {
        bytearrayoutputstream    bout = new bytearrayoutputstream();
        
        this.encode(bout);
        
        return bout.tobytearray();
    }
    
    public void encode(
        outputstream    outstream) 
        throws ioexception
    {
        for (int i = 0; i != keys.size(); i++)
        {
            pgpsecretkey    k = (pgpsecretkey)keys.get(i);
            
            k.encode(outstream);
        }
        for (int i = 0; i != extrapubkeys.size(); i++)
        {
            pgppublickey    k = (pgppublickey)extrapubkeys.get(i);

            k.encode(outstream);
        }
    }

    /**
     * replace the public key set on the secret ring with the corresponding key off the public ring.
     *
     * @param secretring secret ring to be changed.
     * @param publicring public ring containing the new public key set.
     */
    public static pgpsecretkeyring replacepublickeys(pgpsecretkeyring secretring, pgppublickeyring publicring)
    {
        list newlist = new arraylist(secretring.keys.size());

        for (iterator it = secretring.keys.iterator(); it.hasnext();)
        {
            pgpsecretkey sk = (pgpsecretkey)it.next();
            pgppublickey pk = publicring.getpublickey(sk.getkeyid());

            newlist.add(pgpsecretkey.replacepublickey(sk, pk));
        }

        return new pgpsecretkeyring(newlist);
    }

    /**
     * return a copy of the passed in secret key ring, with the master key and sub keys encrypted
     * using a new password and the passed in algorithm.
     *
     * @param ring the pgpsecretkeyring to be copied.
     * @param oldpassphrase the current password for key.
     * @param newpassphrase the new password for the key.
     * @param newencalgorithm the algorithm to be used for the encryption.
     * @param rand source of randomness.
     * @param provider name of the provider to use
     * @deprecated  use version taking pbesecretkeyencryptor/pbesecretkeydecryptor
     */
    public static pgpsecretkeyring copywithnewpassword(
        pgpsecretkeyring ring,
        char[]           oldpassphrase,
        char[]           newpassphrase,
        int              newencalgorithm,
        securerandom     rand,
        string           provider)
        throws pgpexception, nosuchproviderexception
    {
        return copywithnewpassword(ring, oldpassphrase, newpassphrase, newencalgorithm, rand, pgputil.getprovider(provider));
    }

    /**
     * return a copy of the passed in secret key ring, with the master key and sub keys encrypted
     * using a new password and the passed in algorithm.
     *
     * @param ring the pgpsecretkeyring to be copied.
     * @param oldpassphrase the current password for key.
     * @param newpassphrase the new password for the key.
     * @param newencalgorithm the algorithm to be used for the encryption.
     * @param rand source of randomness.
     * @param provider provider to use
     * @deprecated  use version taking pbesecretkeyencryptor/pbesecretkeydecryptor
     */
    public static pgpsecretkeyring copywithnewpassword(
        pgpsecretkeyring ring,
        char[]           oldpassphrase,
        char[]           newpassphrase,
        int              newencalgorithm,
        securerandom     rand,
        provider         provider)
        throws pgpexception
    {
        list newkeys = new arraylist(ring.keys.size());

        for (iterator keys = ring.getsecretkeys(); keys.hasnext();)
        {
            newkeys.add(pgpsecretkey.copywithnewpassword((pgpsecretkey)keys.next(), oldpassphrase, newpassphrase, newencalgorithm, rand, provider));
        }

        return new pgpsecretkeyring(newkeys, ring.extrapubkeys);
    }

    /**
     * return a copy of the passed in secret key ring, with the private keys (where present) associated with the master key and sub keys
     * are encrypted using a new password and the passed in algorithm.
     *
     * @param ring the pgpsecretkeyring to be copied.
     * @param oldkeydecryptor the current decryptor based on the current password for key.
     * @param newkeyencryptor a new encryptor based on a new password for encrypting the secret key material.
     * @return the updated key ring.
     */
    public static pgpsecretkeyring copywithnewpassword(
        pgpsecretkeyring       ring,
        pbesecretkeydecryptor  oldkeydecryptor,
        pbesecretkeyencryptor  newkeyencryptor)
        throws pgpexception
    {
        list newkeys = new arraylist(ring.keys.size());

        for (iterator keys = ring.getsecretkeys(); keys.hasnext();)
        {
            pgpsecretkey key = (pgpsecretkey)keys.next();

            if (key.isprivatekeyempty())
            {
                newkeys.add(key);
            }
            else
            {
                newkeys.add(pgpsecretkey.copywithnewpassword(key, oldkeydecryptor, newkeyencryptor));
            }
        }

        return new pgpsecretkeyring(newkeys, ring.extrapubkeys);
    }

    /**
     * returns a new key ring with the secret key passed in either added or
     * replacing an existing one with the same key id.
     * 
     * @param secring the secret key ring to be modified.
     * @param seckey the secret key to be added.
     * @return a new secret key ring.
     */
    public static pgpsecretkeyring insertsecretkey(
        pgpsecretkeyring  secring,
        pgpsecretkey      seckey)
    {
        list       keys = new arraylist(secring.keys);
        boolean    found = false;
        boolean    masterfound = false;
        
        for (int i = 0; i != keys.size();i++)
        {
            pgpsecretkey   key = (pgpsecretkey)keys.get(i);
            
            if (key.getkeyid() == seckey.getkeyid())
            {
                found = true;
                keys.set(i, seckey);
            }
            if (key.ismasterkey())
            {
                masterfound = true;
            }
        }

        if (!found)
        {
            if (seckey.ismasterkey())
            {
                if (masterfound)
                {
                    throw new illegalargumentexception("cannot add a master key to a ring that already has one");
                }

                keys.add(0, seckey);
            }
            else
            {
                keys.add(seckey);
            }
        }
        
        return new pgpsecretkeyring(keys, secring.extrapubkeys);
    }
    
    /**
     * returns a new key ring with the secret key passed in removed from the
     * key ring.
     * 
     * @param secring the secret key ring to be modified.
     * @param seckey the secret key to be removed.
     * @return a new secret key ring, or null if seckey is not found.
     */
    public static pgpsecretkeyring removesecretkey(
        pgpsecretkeyring  secring,
        pgpsecretkey      seckey)
    {
        list       keys = new arraylist(secring.keys);
        boolean    found = false;
        
        for (int i = 0; i < keys.size();i++)
        {
            pgpsecretkey   key = (pgpsecretkey)keys.get(i);
            
            if (key.getkeyid() == seckey.getkeyid())
            {
                found = true;
                keys.remove(i);
            }
        }
        
        if (!found)
        {
            return null;
        }
        
        return new pgpsecretkeyring(keys, secring.extrapubkeys);
    }
}
