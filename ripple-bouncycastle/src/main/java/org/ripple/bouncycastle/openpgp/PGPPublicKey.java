package org.ripple.bouncycastle.openpgp;

import java.io.bytearrayoutputstream;
import java.io.ioexception;
import java.io.outputstream;
import java.security.nosuchproviderexception;
import java.security.provider;
import java.security.publickey;
import java.util.arraylist;
import java.util.collection;
import java.util.date;
import java.util.iterator;
import java.util.list;

import org.ripple.bouncycastle.bcpg.bcpgkey;
import org.ripple.bouncycastle.bcpg.bcpgoutputstream;
import org.ripple.bouncycastle.bcpg.containedpacket;
import org.ripple.bouncycastle.bcpg.dsapublicbcpgkey;
import org.ripple.bouncycastle.bcpg.elgamalpublicbcpgkey;
import org.ripple.bouncycastle.bcpg.publickeyalgorithmtags;
import org.ripple.bouncycastle.bcpg.publickeypacket;
import org.ripple.bouncycastle.bcpg.rsapublicbcpgkey;
import org.ripple.bouncycastle.bcpg.trustpacket;
import org.ripple.bouncycastle.bcpg.userattributepacket;
import org.ripple.bouncycastle.bcpg.useridpacket;
import org.ripple.bouncycastle.openpgp.operator.keyfingerprintcalculator;
import org.ripple.bouncycastle.openpgp.operator.jcajce.jcapgpkeyconverter;
import org.ripple.bouncycastle.util.arrays;

/**
 * general class to handle a pgp public key object.
 */
public class pgppublickey
    implements publickeyalgorithmtags
{
    private static final int[] master_key_certification_types = new int[] { pgpsignature.positive_certification, pgpsignature.casual_certification, pgpsignature.no_certification, pgpsignature.default_certification };
    
    publickeypacket publicpk;
    trustpacket     trustpk;
    list            keysigs = new arraylist();
    list            ids = new arraylist();
    list            idtrusts = new arraylist();
    list            idsigs = new arraylist();
    
    list            subsigs = null;

    private long    keyid;
    private byte[]  fingerprint;
    private int     keystrength;

    private void init(keyfingerprintcalculator fingerprintcalculator)
        throws pgpexception
    {
        bcpgkey                key = publicpk.getkey();

        this.fingerprint = fingerprintcalculator.calculatefingerprint(publicpk);

        if (publicpk.getversion() <= 3)
        {
            rsapublicbcpgkey    rk = (rsapublicbcpgkey)key;
            
            this.keyid = rk.getmodulus().longvalue();
            this.keystrength = rk.getmodulus().bitlength();
        }
        else
        {
            this.keyid = ((long)(fingerprint[fingerprint.length - 8] & 0xff) << 56)
                            | ((long)(fingerprint[fingerprint.length - 7] & 0xff) << 48)
                            | ((long)(fingerprint[fingerprint.length - 6] & 0xff) << 40)
                            | ((long)(fingerprint[fingerprint.length - 5] & 0xff) << 32)
                            | ((long)(fingerprint[fingerprint.length - 4] & 0xff) << 24)
                            | ((long)(fingerprint[fingerprint.length - 3] & 0xff) << 16)
                            | ((long)(fingerprint[fingerprint.length - 2] & 0xff) << 8)
                            | ((fingerprint[fingerprint.length - 1] & 0xff));
            
            if (key instanceof rsapublicbcpgkey)
            {
                this.keystrength = ((rsapublicbcpgkey)key).getmodulus().bitlength();
            }
            else if (key instanceof dsapublicbcpgkey)
            {
                this.keystrength = ((dsapublicbcpgkey)key).getp().bitlength();
            }
            else if (key instanceof elgamalpublicbcpgkey)
            {
                this.keystrength = ((elgamalpublicbcpgkey)key).getp().bitlength();
            }
        }
    }
    
    /**
     * create a pgppublickey from the passed in jca one.
     * <p>
     * note: the time passed in affects the value of the key's keyid, so you probably only want
     * to do this once for a jca key, or make sure you keep track of the time you used.
     * 
     * @param algorithm asymmetric algorithm type representing the public key.
     * @param pubkey actual public key to associate.
     * @param time date of creation.
     * @param provider provider to use for underlying digest calculations.
     * @throws pgpexception on key creation problem.
     * @throws nosuchproviderexception if the specified provider is required and cannot be found.
     * @deprecated use jcapgpkeyconverter.getpgppublickey()
     */
    public pgppublickey(
        int            algorithm,
        publickey      pubkey,
        date           time,
        string         provider) 
        throws pgpexception, nosuchproviderexception
    {
        this(new jcapgpkeyconverter().setprovider(provider).getpgppublickey(algorithm, pubkey, time));
    }

    /**
         * @deprecated use jcapgpkeyconverter.getpgppublickey()
     */
    public pgppublickey(
        int            algorithm,
        publickey      pubkey,
        date           time)
        throws pgpexception
    {
        this(new jcapgpkeyconverter().getpgppublickey(algorithm, pubkey, time));
    }

    /**
     * create a pgp public key from a packet descriptor using the passed in fingerprintcalculator to do calculate
     * the fingerprint and keyid.
     *
     * @param publickeypacket  packet describing the public key.
     * @param fingerprintcalculator calculator providing the digest support ot create the key fingerprint.
     * @throws pgpexception  if the packet is faulty, or the required calculations fail.
     */
    public pgppublickey(publickeypacket publickeypacket, keyfingerprintcalculator fingerprintcalculator)
        throws pgpexception
    {
        this.publicpk = publickeypacket;
        this.ids = new arraylist();
        this.idsigs = new arraylist();

        init(fingerprintcalculator);
    }

    /*
     * constructor for a sub-key.
     */
    pgppublickey(
        publickeypacket publicpk, 
        trustpacket     trustpk, 
        list            sigs,
        keyfingerprintcalculator fingerprintcalculator)
        throws pgpexception
     {
        this.publicpk = publicpk;
        this.trustpk = trustpk;
        this.subsigs = sigs;
        
        init(fingerprintcalculator);
     }

    pgppublickey(
        pgppublickey key,
        trustpacket trust, 
        list        subsigs)
    {
        this.publicpk = key.publicpk;
        this.trustpk = trust;
        this.subsigs = subsigs;
                
        this.fingerprint = key.fingerprint;
        this.keyid = key.keyid;
        this.keystrength = key.keystrength;
    }
    
    /**
     * copy constructor.
     * @param pubkey the public key to copy.
     */
    pgppublickey(
        pgppublickey    pubkey)
     {
        this.publicpk = pubkey.publicpk;
        
        this.keysigs = new arraylist(pubkey.keysigs);
        this.ids = new arraylist(pubkey.ids);
        this.idtrusts = new arraylist(pubkey.idtrusts);
        this.idsigs = new arraylist(pubkey.idsigs.size());
        for (int i = 0; i != pubkey.idsigs.size(); i++)
        {
            this.idsigs.add(new arraylist((arraylist)pubkey.idsigs.get(i)));
        }
       
        if (pubkey.subsigs != null)
        {
            this.subsigs = new arraylist(pubkey.subsigs.size());
            for (int i = 0; i != pubkey.subsigs.size(); i++)
            {
                this.subsigs.add(pubkey.subsigs.get(i));
            }
        }
        
        this.fingerprint = pubkey.fingerprint;
        this.keyid = pubkey.keyid;
        this.keystrength = pubkey.keystrength;
     }

    pgppublickey(
        publickeypacket publicpk,
        trustpacket     trustpk,
        list            keysigs,
        list            ids,
        list            idtrusts,
        list            idsigs,
        keyfingerprintcalculator fingerprintcalculator)
        throws pgpexception
    {
        this.publicpk = publicpk;
        this.trustpk = trustpk;
        this.keysigs = keysigs;
        this.ids = ids;
        this.idtrusts = idtrusts;
        this.idsigs = idsigs;
    
        init(fingerprintcalculator);
    }
    
    /**
     * @return the version of this key.
     */
    public int getversion()
    {
        return publicpk.getversion();
    }
    
    /**
     * @return creation time of key.
     */
    public date getcreationtime()
    {
        return publicpk.gettime();
    }
    
    /**
     * @return number of valid days from creation time - zero means no
     * expiry.
     */
    public int getvaliddays()
    {
        if (publicpk.getversion() > 3)
        {
            return (int)(this.getvalidseconds() / (24 * 60 * 60));
        }
        else
        {
            return publicpk.getvaliddays();
        }
    }

    /**
     * return the trust data associated with the public key, if present.
     * @return a byte array with trust data, null otherwise.
     */
    public byte[] gettrustdata()
    {
        if (trustpk == null)
        {
            return null;
        }

        return arrays.clone(trustpk.getlevelandtrustamount());
    }

    /**
     * @return number of valid seconds from creation time - zero means no
     * expiry.
     */
    public long getvalidseconds()
    {
        if (publicpk.getversion() > 3)
        {
            if (this.ismasterkey())
            {
                for (int i = 0; i != master_key_certification_types.length; i++)
                {
                    long seconds = getexpirationtimefromsig(true, master_key_certification_types[i]);
                    
                    if (seconds >= 0)
                    {
                        return seconds;
                    }
                }
            }
            else
            {
                long seconds = getexpirationtimefromsig(false, pgpsignature.subkey_binding);
                
                if (seconds >= 0)
                {
                    return seconds;
                }
            }
            
            return 0;
        }
        else
        {
            return (long)publicpk.getvaliddays() * 24 * 60 * 60;
        }
    }

    private long getexpirationtimefromsig(
        boolean selfsigned,
        int signaturetype) 
    {
        iterator signatures = this.getsignaturesoftype(signaturetype);
        long     expirytime = -1;

        while (signatures.hasnext())
        {
            pgpsignature sig = (pgpsignature)signatures.next();

            if (!selfsigned || sig.getkeyid() == this.getkeyid())
            {
                pgpsignaturesubpacketvector hashed = sig.gethashedsubpackets();
                
                if (hashed != null)
                {
                    long current = hashed.getkeyexpirationtime();

                    if (current == 0 || current > expirytime)
                    {
                        expirytime = current;
                    }
                }
                else
                {
                    return 0;
                }
            }
        }
        
        return expirytime;
    }
    
    /**
     * return the keyid associated with the public key.
     * 
     * @return long
     */
    public long getkeyid()
    {
        return keyid;
    }
    
    /**
     * return the fingerprint of the key.
     * 
     * @return key fingerprint.
     */
    public byte[] getfingerprint()
    {
        byte[]    tmp = new byte[fingerprint.length];
        
        system.arraycopy(fingerprint, 0, tmp, 0, tmp.length);
        
        return tmp;
    }
    
    /**
     * return true if this key has an algorithm type that makes it suitable to use for encryption.
     * <p>
     * note: with version 4 keys keyflags subpackets should also be considered when present for
     * determining the preferred use of the key.
     *
     * @return true if the key algorithm is suitable for encryption.
     */
    public boolean isencryptionkey()
    {
        int algorithm = publicpk.getalgorithm();

        return ((algorithm == rsa_general) || (algorithm == rsa_encrypt)
                || (algorithm == elgamal_encrypt) || (algorithm == elgamal_general));
    }

    /**
     * return true if this is a master key.
     * @return true if a master key.
     */
    public boolean ismasterkey()
    {
        return (subsigs == null);
    }
    
    /**
     * return the algorithm code associated with the public key.
     * 
     * @return int
     */
    public int getalgorithm()
    {
        return publicpk.getalgorithm();
    }
    
    /**
     * return the strength of the key in bits.
     * 
     * @return bit strenght of key.
     */
    public int getbitstrength()
    {
        return keystrength;
    }

    /**
     * return the public key contained in the object.
     * 
     * @param provider provider to construct the key for.
     * @return a jce/jca public key.
     * @throws pgpexception if the key algorithm is not recognised.
     * @throws nosuchproviderexception if the provider cannot be found.
     * @deprecated use a jcapgpkeyconverter
     */
    public publickey getkey(
        string provider)
        throws pgpexception, nosuchproviderexception
    {
        return new jcapgpkeyconverter().setprovider(provider).getpublickey(this);
    }

    /**
     * return the public key contained in the object.
     *
     * @param provider provider to construct the key for.
     * @return a jce/jca public key.
     * @throws pgpexception if the key algorithm is not recognised.
     * @deprecated use a jcapgpkeyconverter
     */
    public publickey getkey(
        provider provider)
        throws pgpexception
    {
        return new jcapgpkeyconverter().setprovider(provider).getpublickey(this);
    }

    /**
     * return any userids associated with the key.
     * 
     * @return an iterator of strings.
     */
    public iterator getuserids()
    {
        list    temp = new arraylist();
        
        for (int i = 0; i != ids.size(); i++)
        {
            if (ids.get(i) instanceof string)
            {
                temp.add(ids.get(i));
            }
        }
        
        return temp.iterator();
    }
    
    /**
     * return any user attribute vectors associated with the key.
     * 
     * @return an iterator of pgpuserattributesubpacketvector objects.
     */
    public iterator getuserattributes()
    {
        list    temp = new arraylist();
        
        for (int i = 0; i != ids.size(); i++)
        {
            if (ids.get(i) instanceof pgpuserattributesubpacketvector)
            {
                temp.add(ids.get(i));
            }
        }
        
        return temp.iterator();
    }
    
    /**
     * return any signatures associated with the passed in id.
     * 
     * @param id the id to be matched.
     * @return an iterator of pgpsignature objects.
     */
    public iterator getsignaturesforid(
        string   id)
    {
        for (int i = 0; i != ids.size(); i++)
        {
            if (id.equals(ids.get(i)))
            {
                return ((arraylist)idsigs.get(i)).iterator();
            }
        }
        
        return null;
    }
    
    /**
     * return an iterator of signatures associated with the passed in user attributes.
     * 
     * @param userattributes the vector of user attributes to be matched.
     * @return an iterator of pgpsignature objects.
     */
    public iterator getsignaturesforuserattribute(
        pgpuserattributesubpacketvector    userattributes)
    {
        for (int i = 0; i != ids.size(); i++)
        {
            if (userattributes.equals(ids.get(i)))
            {
                return ((arraylist)idsigs.get(i)).iterator();
            }
        }
        
        return null;
    }
    
    /**
     * return signatures of the passed in type that are on this key.
     * 
     * @param signaturetype the type of the signature to be returned.
     * @return an iterator (possibly empty) of signatures of the given type.
     */
    public iterator getsignaturesoftype(
        int signaturetype)
    {
        list        l = new arraylist();
        iterator    it = this.getsignatures();
        
        while (it.hasnext())
        {
            pgpsignature    sig = (pgpsignature)it.next();
            
            if (sig.getsignaturetype() == signaturetype)
            {
                l.add(sig);
            }
        }
        
        return l.iterator();
    }
    
    /**
     * return all signatures/certifications associated with this key.
     * 
     * @return an iterator (possibly empty) with all signatures/certifications.
     */
    public iterator getsignatures()
    {
        if (subsigs == null)
        {
            list sigs = new arraylist();

            sigs.addall(keysigs);

            for (int i = 0; i != idsigs.size(); i++)
            {
                sigs.addall((collection)idsigs.get(i));
            }
            
            return sigs.iterator();
        }
        else
        {
            return subsigs.iterator();
        }
    }

    public publickeypacket getpublickeypacket()
    {
        return publicpk;
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
        bcpgoutputstream    out;
        
        if (outstream instanceof bcpgoutputstream)
        {
            out = (bcpgoutputstream)outstream;
        }
        else
        {
            out = new bcpgoutputstream(outstream);
        }
        
        out.writepacket(publicpk);
        if (trustpk != null)
        {
            out.writepacket(trustpk);
        }
        
        if (subsigs == null)    // not a sub-key
        {
            for (int i = 0; i != keysigs.size(); i++)
            {
                ((pgpsignature)keysigs.get(i)).encode(out);
            }
            
            for (int i = 0; i != ids.size(); i++)
            {
                if (ids.get(i) instanceof string)
                {
                    string    id = (string)ids.get(i);
                    
                    out.writepacket(new useridpacket(id));
                }
                else
                {
                    pgpuserattributesubpacketvector    v = (pgpuserattributesubpacketvector)ids.get(i);

                    out.writepacket(new userattributepacket(v.tosubpacketarray()));
                }
                
                if (idtrusts.get(i) != null)
                {
                    out.writepacket((containedpacket)idtrusts.get(i));
                }
                
                list    sigs = (list)idsigs.get(i);
                for (int j = 0; j != sigs.size(); j++)
                {
                    ((pgpsignature)sigs.get(j)).encode(out);
                }
            }
        }
        else
        {
            for (int j = 0; j != subsigs.size(); j++)
            {
                ((pgpsignature)subsigs.get(j)).encode(out);
            }
        }
    }
    
    /**
     * check whether this (sub)key has a revocation signature on it.
     * 
     * @return boolean indicating whether this (sub)key has been revoked.
     */
    public boolean isrevoked()
    {
        int ns = 0;
        boolean revoked = false;

        if (this.ismasterkey())    // master key
        {
            while (!revoked && (ns < keysigs.size()))
            {
                if (((pgpsignature)keysigs.get(ns++)).getsignaturetype() == pgpsignature.key_revocation)
                {
                    revoked = true;
                }
            }
        }
        else                    // sub-key
        {
            while (!revoked && (ns < subsigs.size()))
            {
                if (((pgpsignature)subsigs.get(ns++)).getsignaturetype() == pgpsignature.subkey_revocation)
                {
                    revoked = true;
                }
            }
        }

        return revoked;
    }


    /**
     * add a certification for an id to the given public key.
     * 
     * @param key the key the certification is to be added to.
     * @param id the id the certification is associated with.
     * @param certification the new certification.
     * @return the re-certified key.
     */
    public static pgppublickey addcertification(
        pgppublickey    key,
        string          id,
        pgpsignature    certification)
    {
        return addcert(key, id, certification);
    }

    /**
     * add a certification for the given userattributesubpackets to the given public key.
     *
     * @param key the key the certification is to be added to.
     * @param userattributes the attributes the certification is associated with.
     * @param certification the new certification.
     * @return the re-certified key.
     */
    public static pgppublickey addcertification(
        pgppublickey                    key,
        pgpuserattributesubpacketvector userattributes,
        pgpsignature                    certification)
    {
        return addcert(key, userattributes, certification);
    }

    private static pgppublickey addcert(
        pgppublickey  key,
        object        id,
        pgpsignature  certification)
    {
        pgppublickey    returnkey = new pgppublickey(key);
        list            siglist = null;

        for (int i = 0; i != returnkey.ids.size(); i++)
        {
            if (id.equals(returnkey.ids.get(i)))
            {
                siglist = (list)returnkey.idsigs.get(i);
            }
        }

        if (siglist != null)
        {
            siglist.add(certification);
        }
        else
        {
            siglist = new arraylist();

            siglist.add(certification);
            returnkey.ids.add(id);
            returnkey.idtrusts.add(null);
            returnkey.idsigs.add(siglist);
        }

        return returnkey;
    }

    /**
     * remove any certifications associated with a given user attribute subpacket
     *  on a key.
     * 
     * @param key the key the certifications are to be removed from.
     * @param userattributes the attributes to be removed.
     * @return the re-certified key, null if the user attribute subpacket was not found on the key.
     */
    public static pgppublickey removecertification(
        pgppublickey                    key,
        pgpuserattributesubpacketvector userattributes)
    {
        return removecert(key, userattributes);
    }

    /**
     * remove any certifications associated with a given id on a key.
     *
     * @param key the key the certifications are to be removed from.
     * @param id the id that is to be removed.
     * @return the re-certified key, null if the id was not found on the key.
     */
    public static pgppublickey removecertification(
        pgppublickey    key,
        string          id)
    {
        return removecert(key, id);
    }

    private static pgppublickey removecert(
        pgppublickey    key,
        object          id)
    {
        pgppublickey    returnkey = new pgppublickey(key);
        boolean         found = false;

        for (int i = 0; i < returnkey.ids.size(); i++)
        {
            if (id.equals(returnkey.ids.get(i)))
            {
                found = true;
                returnkey.ids.remove(i);
                returnkey.idtrusts.remove(i);
                returnkey.idsigs.remove(i);
            }
        }

        if (!found)
        {
            return null;
        }

        return returnkey;
    }

    /**
     * remove a certification associated with a given id on a key.
     * 
     * @param key the key the certifications are to be removed from.
     * @param id the id that the certification is to be removed from.
     * @param certification the certification to be removed.
     * @return the re-certified key, null if the certification was not found.
     */
    public static pgppublickey removecertification(
        pgppublickey    key,
        string          id,
        pgpsignature    certification)
    {
        return removecert(key, id, certification);
    }

    /**
     * remove a certification associated with a given user attributes on a key.
     *
     * @param key the key the certifications are to be removed from.
     * @param userattributes the user attributes that the certification is to be removed from.
     * @param certification the certification to be removed.
     * @return the re-certified key, null if the certification was not found.
     */
    public static pgppublickey removecertification(
        pgppublickey                     key,
        pgpuserattributesubpacketvector  userattributes,
        pgpsignature                     certification)
    {
        return removecert(key, userattributes, certification);
    }

    private static pgppublickey removecert(
        pgppublickey    key,
        object          id,
        pgpsignature    certification)
    {
        pgppublickey    returnkey = new pgppublickey(key);
        boolean         found = false;

        for (int i = 0; i < returnkey.ids.size(); i++)
        {
            if (id.equals(returnkey.ids.get(i)))
            {
                found = ((list)returnkey.idsigs.get(i)).remove(certification);
            }
        }

        if (!found)
        {
            return null;
        }

        return returnkey;
    }

    /**
     * add a revocation or some other key certification to a key.
     * 
     * @param key the key the revocation is to be added to.
     * @param certification the key signature to be added.
     * @return the new changed public key object.
     */
    public static pgppublickey addcertification(
        pgppublickey    key,
        pgpsignature    certification)
    {
        if (key.ismasterkey())
        {
            if (certification.getsignaturetype() == pgpsignature.subkey_revocation)
            {
                throw new illegalargumentexception("signature type incorrect for master key revocation.");
            }
        }
        else
        {
            if (certification.getsignaturetype() == pgpsignature.key_revocation)
            {
                throw new illegalargumentexception("signature type incorrect for sub-key revocation.");
            }
        }

        pgppublickey    returnkey = new pgppublickey(key);
        
        if (returnkey.subsigs != null)
        {
            returnkey.subsigs.add(certification);
        }
        else
        {
            returnkey.keysigs.add(certification);
        }
        
        return returnkey;
    }

    /**
     * remove a certification from the key.
     *
     * @param key the key the certifications are to be removed from.
     * @param certification the certification to be removed.
     * @return the modified key, null if the certification was not found.
     */
    public static pgppublickey removecertification(
        pgppublickey    key,
        pgpsignature    certification)
    {
        pgppublickey    returnkey = new pgppublickey(key);
        boolean         found;

        if (returnkey.subsigs != null)
        {
            found = returnkey.subsigs.remove(certification);
        }
        else
        {
            found = returnkey.keysigs.remove(certification);
        }

        if (!found)
        {
            for (iterator it = key.getuserids(); it.hasnext();)
            {
                string id = (string)it.next();
                for (iterator sit = key.getsignaturesforid(id); sit.hasnext();)
                {
                    if (certification == sit.next())
                    {
                        found = true;
                        returnkey = pgppublickey.removecertification(returnkey, id, certification);
                    }
                }
            }

            if (!found)
            {
                for (iterator it = key.getuserattributes(); it.hasnext();)
                {
                    pgpuserattributesubpacketvector id = (pgpuserattributesubpacketvector)it.next();
                    for (iterator sit = key.getsignaturesforuserattribute(id); sit.hasnext();)
                    {
                        if (certification == sit.next())
                        {
                            found = true;
                            returnkey = pgppublickey.removecertification(returnkey, id, certification);
                        }
                    }
                }
            }
        }

        return returnkey;
    }
}
