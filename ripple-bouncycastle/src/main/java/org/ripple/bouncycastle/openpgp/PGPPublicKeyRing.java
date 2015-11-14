package org.ripple.bouncycastle.openpgp;

import java.io.bytearrayinputstream;
import java.io.bytearrayoutputstream;
import java.io.ioexception;
import java.io.inputstream;
import java.io.outputstream;
import java.util.arraylist;
import java.util.collections;
import java.util.iterator;
import java.util.list;

import org.ripple.bouncycastle.bcpg.bcpginputstream;
import org.ripple.bouncycastle.bcpg.packettags;
import org.ripple.bouncycastle.bcpg.publickeypacket;
import org.ripple.bouncycastle.bcpg.trustpacket;
import org.ripple.bouncycastle.openpgp.operator.keyfingerprintcalculator;
import org.ripple.bouncycastle.openpgp.operator.jcajce.jcakeyfingerprintcalculator;

/**
 * class to hold a single master public key and its subkeys.
 * <p>
 * often pgp keyring files consist of multiple master keys, if you are trying to process
 * or construct one of these you should use the pgppublickeyringcollection class.
 */
public class pgppublickeyring
    extends pgpkeyring
{
    list keys;

    /**
     * @deprecated use version that takes a keyfingerprintcalculator
     */
    public pgppublickeyring(
        byte[]    encoding)
        throws ioexception
    {
        this(new bytearrayinputstream(encoding), new jcakeyfingerprintcalculator());
    }

    public pgppublickeyring(
        byte[]    encoding,
        keyfingerprintcalculator fingerprintcalculator)
        throws ioexception
    {
        this(new bytearrayinputstream(encoding), fingerprintcalculator);
    }

    /**
     * @param pubkeys
     */
    pgppublickeyring(
        list pubkeys)
    {
        this.keys = pubkeys;
    }

    /**
     * @deprecated use version that takes a keyfingerprintcalculator
     */
    public pgppublickeyring(
        inputstream    in)
        throws ioexception
    {
        this(in, new jcakeyfingerprintcalculator());
    }

    public pgppublickeyring(
        inputstream    in,
        keyfingerprintcalculator fingerprintcalculator)
        throws ioexception
    {
        this.keys = new arraylist();

        bcpginputstream pin = wrap(in);

        int initialtag = pin.nextpackettag();
        if (initialtag != packettags.public_key && initialtag != packettags.public_subkey)
        {
            throw new ioexception(
                "public key ring doesn't start with public key tag: " +
                "tag 0x" + integer.tohexstring(initialtag));
        }

        publickeypacket pubpk = (publickeypacket)pin.readpacket();
        trustpacket     trustpk = readoptionaltrustpacket(pin);

        // direct signatures and revocations
        list keysigs = readsignaturesandtrust(pin);

        list ids = new arraylist();
        list idtrusts = new arraylist();
        list idsigs = new arraylist();
        readuserids(pin, ids, idtrusts, idsigs);

        try
        {
            keys.add(new pgppublickey(pubpk, trustpk, keysigs, ids, idtrusts, idsigs, fingerprintcalculator));

            // read subkeys
            while (pin.nextpackettag() == packettags.public_subkey)
            {
                keys.add(readsubkey(pin, fingerprintcalculator));
            }
        }
        catch (pgpexception e)
        {
            throw new ioexception("processing exception: " + e.tostring());
        }
    }

    /**
     * return the first public key in the ring.
     * 
     * @return pgppublickey
     */
    public pgppublickey getpublickey()
    {
        return (pgppublickey)keys.get(0);
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
        for (int i = 0; i != keys.size(); i++)
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
        return collections.unmodifiablelist(keys).iterator();
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
            pgppublickey    k = (pgppublickey)keys.get(i);
            
            k.encode(outstream);
        }
    }
    
    /**
     * returns a new key ring with the public key passed in
     * either added or replacing an existing one.
     * 
     * @param pubring the public key ring to be modified
     * @param pubkey the public key to be inserted.
     * @return a new keyring
     */
    public static pgppublickeyring insertpublickey(
        pgppublickeyring  pubring,
        pgppublickey      pubkey)
    {
        list       keys = new arraylist(pubring.keys);
        boolean    found = false;
        boolean    masterfound = false;

        for (int i = 0; i != keys.size();i++)
        {
            pgppublickey   key = (pgppublickey)keys.get(i);
            
            if (key.getkeyid() == pubkey.getkeyid())
            {
                found = true;
                keys.set(i, pubkey);
            }
            if (key.ismasterkey())
            {
                masterfound = true;
            }
        }

        if (!found)
        {
            if (pubkey.ismasterkey())
            {
                if (masterfound)
                {
                    throw new illegalargumentexception("cannot add a master key to a ring that already has one");
                }

                keys.add(0, pubkey);
            }
            else
            {
                keys.add(pubkey);
            }
        }
        
        return new pgppublickeyring(keys);
    }
    
    /**
     * returns a new key ring with the public key passed in
     * removed from the key ring.
     * 
     * @param pubring the public key ring to be modified
     * @param pubkey the public key to be removed.
     * @return a new keyring, null if pubkey is not found.
     */
    public static pgppublickeyring removepublickey(
        pgppublickeyring  pubring,
        pgppublickey      pubkey)
    {
        list       keys = new arraylist(pubring.keys);
        boolean    found = false;
        
        for (int i = 0; i < keys.size();i++)
        {
            pgppublickey   key = (pgppublickey)keys.get(i);
            
            if (key.getkeyid() == pubkey.getkeyid())
            {
                found = true;
                keys.remove(i);
            }
        }
        
        if (!found)
        {
            return null;
        }
        
        return new pgppublickeyring(keys);
    }

    static pgppublickey readsubkey(bcpginputstream in, keyfingerprintcalculator fingerprintcalculator)
        throws ioexception, pgpexception
    {
        publickeypacket pk = (publickeypacket)in.readpacket();
        trustpacket     ktrust = readoptionaltrustpacket(in);

        // pgp 8 actually leaves out the signature.
        list siglist = readsignaturesandtrust(in);

        return new pgppublickey(pk, ktrust, siglist, fingerprintcalculator);
    }
}
