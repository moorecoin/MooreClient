package org.ripple.bouncycastle.openpgp;

import java.security.nosuchproviderexception;
import java.security.provider;
import java.security.securerandom;
import java.util.arraylist;
import java.util.iterator;
import java.util.list;

import org.ripple.bouncycastle.bcpg.hashalgorithmtags;
import org.ripple.bouncycastle.bcpg.publicsubkeypacket;
import org.ripple.bouncycastle.openpgp.operator.pbesecretkeyencryptor;
import org.ripple.bouncycastle.openpgp.operator.pgpcontentsignerbuilder;
import org.ripple.bouncycastle.openpgp.operator.pgpdigestcalculator;
import org.ripple.bouncycastle.openpgp.operator.jcajce.jcapgpcontentsignerbuilder;
import org.ripple.bouncycastle.openpgp.operator.jcajce.jcapgpdigestcalculatorproviderbuilder;
import org.ripple.bouncycastle.openpgp.operator.jcajce.jcepbesecretkeyencryptorbuilder;

/**
 * generator for a pgp master and subkey ring. this class will generate
 * both the secret and public key rings
 */
public class pgpkeyringgenerator
{    
    list                                keys = new arraylist();

    private pbesecretkeyencryptor       keyencryptor;
    private pgpdigestcalculator checksumcalculator;
    private pgpkeypair                  masterkey;
    private pgpsignaturesubpacketvector hashedpcks;
    private pgpsignaturesubpacketvector unhashedpcks;
    private pgpcontentsignerbuilder     keysignerbuilder;
    
    /**
     * create a new key ring generator using old style checksumming. it is recommended to use
     * sha1 checksumming where possible.
     * 
     * @param certificationlevel the certification level for keys on this ring.
     * @param masterkey the master key pair.
     * @param id the id to be associated with the ring.
     * @param encalgorithm the algorithm to be used to protect secret keys.
     * @param passphrase the passphrase to be used to protect secret keys.
     * @param hashedpcks packets to be included in the certification hash.
     * @param unhashedpcks packets to be attached unhashed to the certification.
     * @param rand input secured random
     * @param provider the provider to use for encryption.
     * 
     * @throws pgpexception
     * @throws nosuchproviderexception
     * @deprecated   use method taking pbesecretkeydecryptor
     */
    public pgpkeyringgenerator(
        int                            certificationlevel,
        pgpkeypair                     masterkey,
        string                         id,
        int                            encalgorithm,
        char[]                         passphrase,
        pgpsignaturesubpacketvector    hashedpcks,
        pgpsignaturesubpacketvector    unhashedpcks,
        securerandom                   rand,
        string                         provider)
        throws pgpexception, nosuchproviderexception
    {
        this(certificationlevel, masterkey, id, encalgorithm, passphrase, false, hashedpcks, unhashedpcks, rand, provider);
    }

    /**
     * create a new key ring generator.
     * 
     * @param certificationlevel the certification level for keys on this ring.
     * @param masterkey the master key pair.
     * @param id the id to be associated with the ring.
     * @param encalgorithm the algorithm to be used to protect secret keys.
     * @param passphrase the passphrase to be used to protect secret keys.
     * @param usesha1 checksum the secret keys with sha1 rather than the older 16 bit checksum.
     * @param hashedpcks packets to be included in the certification hash.
     * @param unhashedpcks packets to be attached unhashed to the certification.
     * @param rand input secured random
     * @param provider the provider to use for encryption.
     * 
     * @throws pgpexception
     * @throws nosuchproviderexception
     * @deprecated   use method taking pbesecretkeydecryptor
     */
    public pgpkeyringgenerator(
        int                            certificationlevel,
        pgpkeypair                     masterkey,
        string                         id,
        int                            encalgorithm,
        char[]                         passphrase,
        boolean                        usesha1,
        pgpsignaturesubpacketvector    hashedpcks,
        pgpsignaturesubpacketvector    unhashedpcks,
        securerandom                   rand,
        string                         provider)
        throws pgpexception, nosuchproviderexception
    {
        this(certificationlevel, masterkey, id, encalgorithm, passphrase, usesha1, hashedpcks, unhashedpcks, rand, pgputil.getprovider(provider));
    }

    /**
     * create a new key ring generator.
     *
     * @param certificationlevel the certification level for keys on this ring.
     * @param masterkey the master key pair.
     * @param id the id to be associated with the ring.
     * @param encalgorithm the algorithm to be used to protect secret keys.
     * @param passphrase the passphrase to be used to protect secret keys.
     * @param usesha1 checksum the secret keys with sha1 rather than the older 16 bit checksum.
     * @param hashedpcks packets to be included in the certification hash.
     * @param unhashedpcks packets to be attached unhashed to the certification.
     * @param rand input secured random
     * @param provider the provider to use for encryption.
     *
     * @throws pgpexception
     * @throws nosuchproviderexception
     * @deprecated  use method taking pbesecretkeyencryptor
     */
    public pgpkeyringgenerator(
        int                            certificationlevel,
        pgpkeypair                     masterkey,
        string                         id,
        int                            encalgorithm,
        char[]                         passphrase,
        boolean                        usesha1,
        pgpsignaturesubpacketvector    hashedpcks,
        pgpsignaturesubpacketvector    unhashedpcks,
        securerandom                   rand,
        provider                       provider)
        throws pgpexception, nosuchproviderexception
    {
        this.masterkey = masterkey;
        this.hashedpcks = hashedpcks;
        this.unhashedpcks = unhashedpcks;
        this.keyencryptor = new jcepbesecretkeyencryptorbuilder(encalgorithm).setprovider(provider).setsecurerandom(rand).build(passphrase);
        this.checksumcalculator = convertsha1flag(usesha1);
        this.keysignerbuilder = new jcapgpcontentsignerbuilder(masterkey.getpublickey().getalgorithm(), hashalgorithmtags.sha1);

        keys.add(new pgpsecretkey(certificationlevel, masterkey, id, checksumcalculator, hashedpcks, unhashedpcks, keysignerbuilder, keyencryptor));
    }

    /**
     * create a new key ring generator.
     *
     * @param certificationlevel
     * @param masterkey
     * @param id
     * @param checksumcalculator
     * @param hashedpcks
     * @param unhashedpcks
     * @param keysignerbuilder
     * @param keyencryptor
     * @throws pgpexception
     */
    public pgpkeyringgenerator(
        int                            certificationlevel,
        pgpkeypair                     masterkey,
        string                         id,
        pgpdigestcalculator checksumcalculator,
        pgpsignaturesubpacketvector    hashedpcks,
        pgpsignaturesubpacketvector    unhashedpcks,
        pgpcontentsignerbuilder        keysignerbuilder,
        pbesecretkeyencryptor          keyencryptor)
        throws pgpexception
    {
        this.masterkey = masterkey;
        this.keyencryptor = keyencryptor;
        this.checksumcalculator = checksumcalculator;
        this.keysignerbuilder = keysignerbuilder;
        this.hashedpcks = hashedpcks;
        this.unhashedpcks = unhashedpcks;

        keys.add(new pgpsecretkey(certificationlevel, masterkey, id, checksumcalculator, hashedpcks, unhashedpcks, keysignerbuilder, keyencryptor));
    }

    /**
     * add a sub key to the key ring to be generated with default certification and inheriting
     * the hashed/unhashed packets of the master key.
     * 
     * @param keypair
     * @throws pgpexception
     */
    public void addsubkey(
        pgpkeypair    keypair) 
        throws pgpexception
    {
        addsubkey(keypair, hashedpcks, unhashedpcks);
    }
    
    /**
     * add a subkey with specific hashed and unhashed packets associated with it and default
     * certification. 
     * 
     * @param keypair public/private key pair.
     * @param hashedpcks hashed packet values to be included in certification.
     * @param unhashedpcks unhashed packets values to be included in certification.
     * @throws pgpexception
     */
    public void addsubkey(
        pgpkeypair                  keypair,
        pgpsignaturesubpacketvector hashedpcks,
        pgpsignaturesubpacketvector unhashedpcks) 
        throws pgpexception
    {
        try
        {
            //
            // generate the certification
            //
            pgpsignaturegenerator  sgen = new pgpsignaturegenerator(keysignerbuilder);

            sgen.init(pgpsignature.subkey_binding, masterkey.getprivatekey());

            sgen.sethashedsubpackets(hashedpcks);
            sgen.setunhashedsubpackets(unhashedpcks);

            list                 subsigs = new arraylist();
            
            subsigs.add(sgen.generatecertification(masterkey.getpublickey(), keypair.getpublickey()));
            
            keys.add(new pgpsecretkey(keypair.getprivatekey(), new pgppublickey(keypair.getpublickey(), null, subsigs), checksumcalculator, keyencryptor));
        }
        catch (pgpexception e)
        {
            throw e;
        } 
        catch (exception e)
        {
            throw new pgpexception("exception adding subkey: ", e);
        }
    }
    
    /**
     * return the secret key ring.
     * 
     * @return a secret key ring.
     */
    public pgpsecretkeyring generatesecretkeyring()
    {
        return new pgpsecretkeyring(keys);
    }
    
    /**
     * return the public key ring that corresponds to the secret key ring.
     * 
     * @return a public key ring.
     */
    public pgppublickeyring generatepublickeyring()
    {
        iterator it = keys.iterator();
        list     pubkeys = new arraylist();
        
        pubkeys.add(((pgpsecretkey)it.next()).getpublickey());
        
        while (it.hasnext())
        {
            pgppublickey k = new pgppublickey(((pgpsecretkey)it.next()).getpublickey());
            
            k.publicpk = new publicsubkeypacket(k.getalgorithm(), k.getcreationtime(), k.publicpk.getkey());
            
            pubkeys.add(k);
        }
        
        return new pgppublickeyring(pubkeys);
    }

    private static pgpdigestcalculator convertsha1flag(boolean usesha1)
        throws pgpexception
    {
        return usesha1 ? new jcapgpdigestcalculatorproviderbuilder().build().get(hashalgorithmtags.sha1) : null;
    }
}
