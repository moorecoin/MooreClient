package org.ripple.bouncycastle.openpgp;

import java.io.bytearrayinputstream;
import java.io.bytearrayoutputstream;
import java.io.ioexception;
import java.io.outputstream;
import java.security.nosuchproviderexception;
import java.security.privatekey;
import java.security.provider;
import java.security.publickey;
import java.security.securerandom;
import java.util.arraylist;
import java.util.date;
import java.util.iterator;
import java.util.list;

import org.ripple.bouncycastle.bcpg.bcpginputstream;
import org.ripple.bouncycastle.bcpg.bcpgobject;
import org.ripple.bouncycastle.bcpg.bcpgoutputstream;
import org.ripple.bouncycastle.bcpg.containedpacket;
import org.ripple.bouncycastle.bcpg.dsasecretbcpgkey;
import org.ripple.bouncycastle.bcpg.elgamalsecretbcpgkey;
import org.ripple.bouncycastle.bcpg.hashalgorithmtags;
import org.ripple.bouncycastle.bcpg.publickeypacket;
import org.ripple.bouncycastle.bcpg.rsasecretbcpgkey;
import org.ripple.bouncycastle.bcpg.s2k;
import org.ripple.bouncycastle.bcpg.secretkeypacket;
import org.ripple.bouncycastle.bcpg.secretsubkeypacket;
import org.ripple.bouncycastle.bcpg.symmetrickeyalgorithmtags;
import org.ripple.bouncycastle.bcpg.userattributepacket;
import org.ripple.bouncycastle.bcpg.useridpacket;
import org.ripple.bouncycastle.openpgp.operator.pbesecretkeydecryptor;
import org.ripple.bouncycastle.openpgp.operator.pbesecretkeyencryptor;
import org.ripple.bouncycastle.openpgp.operator.pgpcontentsignerbuilder;
import org.ripple.bouncycastle.openpgp.operator.pgpdigestcalculator;
import org.ripple.bouncycastle.openpgp.operator.jcajce.jcapgpcontentsignerbuilder;
import org.ripple.bouncycastle.openpgp.operator.jcajce.jcapgpdigestcalculatorproviderbuilder;
import org.ripple.bouncycastle.openpgp.operator.jcajce.jcepbesecretkeydecryptorbuilder;
import org.ripple.bouncycastle.openpgp.operator.jcajce.jcepbesecretkeyencryptorbuilder;

/**
 * general class to handle a pgp secret key object.
 */
public class pgpsecretkey
{    
    secretkeypacket secret;
    pgppublickey    pub;

    pgpsecretkey(
        secretkeypacket secret,
        pgppublickey    pub)
    {
        this.secret = secret;
        this.pub = pub;
    }
    
    pgpsecretkey(
        pgpprivatekey   privkey,
        pgppublickey    pubkey,
        pgpdigestcalculator checksumcalculator,
        pbesecretkeyencryptor keyencryptor)
        throws pgpexception
    {
        this(privkey, pubkey, checksumcalculator, false, keyencryptor);
    }
    
    pgpsecretkey(
        pgpprivatekey   privkey,
        pgppublickey    pubkey,
        pgpdigestcalculator checksumcalculator,
        boolean         ismasterkey,
        pbesecretkeyencryptor keyencryptor)
        throws pgpexception
    {
        this.pub = pubkey;

        bcpgobject      seckey = (bcpgobject)privkey.getprivatekeydatapacket();

        try
        {
            bytearrayoutputstream   bout = new bytearrayoutputstream();
            bcpgoutputstream        pout = new bcpgoutputstream(bout);
            
            pout.writeobject(seckey);
            
            byte[]    keydata = bout.tobytearray();

            pout.write(checksum(checksumcalculator, keydata, keydata.length));

            int encalgorithm = keyencryptor.getalgorithm();

            if (encalgorithm != symmetrickeyalgorithmtags.null)
            {
                keydata = bout.tobytearray(); // include checksum

                byte[] encdata = keyencryptor.encryptkeydata(keydata, 0, keydata.length);
                byte[] iv = keyencryptor.getcipheriv();

                s2k    s2k = keyencryptor.gets2k();

                int s2kusage;

                if (checksumcalculator != null)
                {
                    if (checksumcalculator.getalgorithm() != hashalgorithmtags.sha1)
                    {
                        throw new pgpexception("only sha1 supported for key checksum calculations.");
                    }
                    s2kusage = secretkeypacket.usage_sha1;
                }
                else
                {
                    s2kusage = secretkeypacket.usage_checksum;
                }

                if (ismasterkey)
                {
                    this.secret = new secretkeypacket(pub.publicpk, encalgorithm, s2kusage, s2k, iv, encdata);
                }
                else
                {
                    this.secret = new secretsubkeypacket(pub.publicpk, encalgorithm, s2kusage, s2k, iv, encdata);
                }
            }
            else
            {
                if (ismasterkey)
                {
                    this.secret = new secretkeypacket(pub.publicpk, encalgorithm, null, null, bout.tobytearray());
                }
                else
                {
                    this.secret = new secretsubkeypacket(pub.publicpk, encalgorithm, null, null, bout.tobytearray());
                }
            }
        }
        catch (pgpexception e)
        {
            throw e;
        }
        catch (exception e)
        {
            throw new pgpexception("exception encrypting key", e);
        }
    }

  /**
        * @deprecated use method taking pbesecretkeyencryptor
     */
    public pgpsecretkey(
        int                         certificationlevel,
        pgpkeypair                  keypair,
        string                      id,
        int                         encalgorithm,
        char[]                      passphrase,
        pgpsignaturesubpacketvector hashedpcks,
        pgpsignaturesubpacketvector unhashedpcks,
        securerandom                rand,
        string                      provider)
        throws pgpexception, nosuchproviderexception
    {
        this(certificationlevel, keypair, id, encalgorithm, passphrase, false, hashedpcks, unhashedpcks, rand, provider);
    }

   /**
        * @deprecated use method taking pbesecretkeyencryptor
     */
    public pgpsecretkey(
        int                         certificationlevel,
        pgpkeypair                  keypair,
        string                      id,
        int                         encalgorithm,
        char[]                      passphrase,
        boolean                     usesha1,
        pgpsignaturesubpacketvector hashedpcks,
        pgpsignaturesubpacketvector unhashedpcks,
        securerandom                rand,
        string                      provider)
        throws pgpexception, nosuchproviderexception
    {
        this(certificationlevel, keypair, id, encalgorithm, passphrase, usesha1, hashedpcks, unhashedpcks, rand, pgputil.getprovider(provider));
    }

    public pgpsecretkey(
        int                         certificationlevel,
        pgpkeypair                  keypair,
        string                      id,
        pgpsignaturesubpacketvector hashedpcks,
        pgpsignaturesubpacketvector unhashedpcks,
        pgpcontentsignerbuilder     certificationsignerbuilder,
        pbesecretkeyencryptor       keyencryptor)
        throws pgpexception
    {
        this(certificationlevel, keypair, id, null, hashedpcks, unhashedpcks, certificationsignerbuilder, keyencryptor);
    }

    /**
        * @deprecated use method taking pbesecretkeyencryptor
     */
    public pgpsecretkey(
        int                         certificationlevel,
        pgpkeypair                  keypair,
        string                      id,
        int                         encalgorithm,
        char[]                      passphrase,
        boolean                     usesha1,
        pgpsignaturesubpacketvector hashedpcks,
        pgpsignaturesubpacketvector unhashedpcks,
        securerandom                rand,
        provider                    provider)
        throws pgpexception
    {
        this(keypair.getprivatekey(), certifiedpublickey(certificationlevel, keypair, id, hashedpcks, unhashedpcks, new jcapgpcontentsignerbuilder(keypair.getpublickey().getalgorithm(), hashalgorithmtags.sha1).setprovider(provider)), convertsha1flag(usesha1), true, new jcepbesecretkeyencryptorbuilder(encalgorithm, new jcapgpdigestcalculatorproviderbuilder().build().get(hashalgorithmtags.sha1)).setprovider(provider).setsecurerandom(rand).build(passphrase));
    }

    private static pgpdigestcalculator convertsha1flag(boolean usesha1)
        throws pgpexception
    {
        return usesha1 ? new jcapgpdigestcalculatorproviderbuilder().build().get(hashalgorithmtags.sha1) : null;
    }

    public pgpsecretkey(
        int                         certificationlevel,
        pgpkeypair                  keypair,
        string                      id,
        pgpdigestcalculator         checksumcalculator,
        pgpsignaturesubpacketvector hashedpcks,
        pgpsignaturesubpacketvector unhashedpcks,
        pgpcontentsignerbuilder     certificationsignerbuilder,
        pbesecretkeyencryptor       keyencryptor)
        throws pgpexception
    {
        this(keypair.getprivatekey(), certifiedpublickey(certificationlevel, keypair, id, hashedpcks, unhashedpcks, certificationsignerbuilder), checksumcalculator, true, keyencryptor);
    }

    private static pgppublickey certifiedpublickey(
        int certificationlevel,
        pgpkeypair keypair,
        string id,
        pgpsignaturesubpacketvector hashedpcks,
        pgpsignaturesubpacketvector unhashedpcks,
        pgpcontentsignerbuilder     certificationsignerbuilder)
        throws pgpexception
    {
        pgpsignaturegenerator    sgen;

        try
        {
            sgen = new pgpsignaturegenerator(certificationsignerbuilder);
        }
        catch (exception e)
        {
            throw new pgpexception("creating signature generator: " + e, e);
        }

        //
        // generate the certification
        //
        sgen.init(certificationlevel, keypair.getprivatekey());

        sgen.sethashedsubpackets(hashedpcks);
        sgen.setunhashedsubpackets(unhashedpcks);

        try
        {
            pgpsignature    certification = sgen.generatecertification(id, keypair.getpublickey());

            return pgppublickey.addcertification(keypair.getpublickey(), id, certification);
        }
        catch (exception e)
        {
            throw new pgpexception("exception doing certification: " + e, e);
        }
    }

      /**
        * @deprecated use method taking pbesecretkeyencryptor
     */
    public pgpsecretkey(
        int                         certificationlevel,
        int                         algorithm,
        publickey                   pubkey,
        privatekey                  privkey,
        date                        time,
        string                      id,
        int                         encalgorithm,
        char[]                      passphrase,
        pgpsignaturesubpacketvector hashedpcks,
        pgpsignaturesubpacketvector unhashedpcks,
        securerandom                rand,
        string                      provider)
        throws pgpexception, nosuchproviderexception
    {
        this(certificationlevel, new pgpkeypair(algorithm,pubkey, privkey, time), id, encalgorithm, passphrase, hashedpcks, unhashedpcks, rand, provider);
    }

      /**
        * @deprecated use method taking pbesecretkeyencryptor
     */
    public pgpsecretkey(
        int                         certificationlevel,
        int                         algorithm,
        publickey                   pubkey,
        privatekey                  privkey,
        date                        time,
        string                      id,
        int                         encalgorithm,
        char[]                      passphrase,
        boolean                     usesha1,
        pgpsignaturesubpacketvector hashedpcks,
        pgpsignaturesubpacketvector unhashedpcks,
        securerandom                rand,
        string                      provider)
        throws pgpexception, nosuchproviderexception
    {
        this(certificationlevel, new pgpkeypair(algorithm, pubkey, privkey, time), id, encalgorithm, passphrase, usesha1, hashedpcks, unhashedpcks, rand, provider);
    }

    /**
     * @deprecated use method taking pgpkeypair
     */
    public pgpsecretkey(
        int                         certificationlevel,
        int                         algorithm,
        publickey                   pubkey,
        privatekey                  privkey,
        date                        time,
        string                      id,
        pgpdigestcalculator         checksumcalculator,
        pgpsignaturesubpacketvector hashedpcks,
        pgpsignaturesubpacketvector unhashedpcks,
        pgpcontentsignerbuilder     certificationsignerbuilder,
        pbesecretkeyencryptor       keyencryptor)
        throws pgpexception
    {
        this(certificationlevel, new pgpkeypair(algorithm, pubkey, privkey, time), id, checksumcalculator, hashedpcks, unhashedpcks, certificationsignerbuilder, keyencryptor);
    }

    /**
     * @deprecated use method taking pgpkeypair
     */
    public pgpsecretkey(
        int                         certificationlevel,
        int                         algorithm,
        publickey                   pubkey,
        privatekey                  privkey,
        date                        time,
        string                      id,
        pgpsignaturesubpacketvector hashedpcks,
        pgpsignaturesubpacketvector unhashedpcks,
        pgpcontentsignerbuilder     certificationsignerbuilder,
        pbesecretkeyencryptor       keyencryptor)
        throws pgpexception, nosuchproviderexception
    {
        this(certificationlevel, new pgpkeypair(algorithm, pubkey, privkey, time), id, null, hashedpcks, unhashedpcks, certificationsignerbuilder, keyencryptor);
    }

    /**
     * return true if this key has an algorithm type that makes it suitable to use for signing.
     * <p>
     * note: with version 4 keys keyflags subpackets should also be considered when present for
     * determining the preferred use of the key.
     *
     * @return true if this key algorithm is suitable for use with signing.
     */
    public boolean issigningkey()
    {
        int algorithm = pub.getalgorithm();

        return ((algorithm == pgppublickey.rsa_general) || (algorithm == pgppublickey.rsa_sign)
                    || (algorithm == pgppublickey.dsa) || (algorithm == pgppublickey.ecdsa) || (algorithm == pgppublickey.elgamal_general));
    }
    
    /**
     * return true if this is a master key.
     * @return true if a master key.
     */
    public boolean ismasterkey()
    {
        return pub.ismasterkey();
    }

    /**
     * detect if the secret key's private key is empty or not
     *
     * @return boolean whether or not the private key is empty
     */
    public boolean isprivatekeyempty()
    {
        byte[] seckeydata = secret.getsecretkeydata();

        return (seckeydata == null || seckeydata.length < 1);
    }

    /**
     * return the algorithm the key is encrypted with.
     *
     * @return the algorithm used to encrypt the secret key.
     */
    public int getkeyencryptionalgorithm()
    {
        return secret.getencalgorithm();
    }

    /**
     * return the keyid of the public key associated with this key.
     * 
     * @return the keyid associated with this key.
     */
    public long getkeyid()
    {
        return pub.getkeyid();
    }
    
    /**
     * return the public key associated with this key.
     * 
     * @return the public key for this key.
     */
    public pgppublickey getpublickey()
    {
        return pub;
    }
    
    /**
     * return any userids associated with the key.
     * 
     * @return an iterator of strings.
     */
    public iterator getuserids()
    {
        return pub.getuserids();
    }
    
    /**
     * return any user attribute vectors associated with the key.
     * 
     * @return an iterator of strings.
     */
    public iterator getuserattributes()
    {
        return pub.getuserattributes();
    }

    private byte[] extractkeydata(
        pbesecretkeydecryptor decryptorfactory)
        throws pgpexception
    {
        byte[] encdata = secret.getsecretkeydata();
        byte[] data = null;

        if (secret.getencalgorithm() != symmetrickeyalgorithmtags.null)
        {
            try
            {
                if (secret.getpublickeypacket().getversion() == 4)
                {
                    byte[] key = decryptorfactory.makekeyfrompassphrase(secret.getencalgorithm(), secret.gets2k());

                    data = decryptorfactory.recoverkeydata(secret.getencalgorithm(), key, secret.getiv(), encdata, 0, encdata.length);

                    boolean usesha1 = secret.gets2kusage() == secretkeypacket.usage_sha1;
                    byte[] check = checksum(usesha1 ? decryptorfactory.getchecksumcalculator(hashalgorithmtags.sha1) : null, data, (usesha1) ? data.length - 20 : data.length - 2);

                    for (int i = 0; i != check.length; i++)
                    {
                        if (check[i] != data[data.length - check.length + i])
                        {
                            throw new pgpexception("checksum mismatch at " + i + " of " + check.length);
                        }
                    }
                }
                else // version 2 or 3, rsa only.
                {
                    byte[] key = decryptorfactory.makekeyfrompassphrase(secret.getencalgorithm(), secret.gets2k());

                    data = new byte[encdata.length];

                    byte[] iv = new byte[secret.getiv().length];

                    system.arraycopy(secret.getiv(), 0, iv, 0, iv.length);

                    //
                    // read in the four numbers
                    //
                    int pos = 0;

                    for (int i = 0; i != 4; i++)
                    {
                        int enclen = (((encdata[pos] << 8) | (encdata[pos + 1] & 0xff)) + 7) / 8;

                        data[pos] = encdata[pos];
                        data[pos + 1] = encdata[pos + 1];

                        byte[] tmp = decryptorfactory.recoverkeydata(secret.getencalgorithm(), key, iv, encdata, pos + 2, enclen);
                        system.arraycopy(tmp, 0, data, pos + 2, tmp.length);
                        pos += 2 + enclen;

                        if (i != 3)
                        {
                            system.arraycopy(encdata, pos - iv.length, iv, 0, iv.length);
                        }
                    }

                    //
                    // verify and copy checksum
                    //

                    data[pos] = encdata[pos];
                    data[pos + 1] = encdata[pos + 1];

                    int cs = ((encdata[pos] << 8) & 0xff00) | (encdata[pos + 1] & 0xff);
                    int calccs = 0;
                    for (int j = 0; j < data.length - 2; j++)
                    {
                        calccs += data[j] & 0xff;
                    }

                    calccs &= 0xffff;
                    if (calccs != cs)
                    {
                        throw new pgpexception("checksum mismatch: passphrase wrong, expected "
                            + integer.tohexstring(cs)
                            + " found " + integer.tohexstring(calccs));
                    }
                }
            }
            catch (pgpexception e)
            {
                throw e;
            }
            catch (exception e)
            {
                throw new pgpexception("exception decrypting key", e);
            }
        }
        else
        {
            data = encdata;
        }

        return data;
    }

    /**
     * extract a pgpprivate key from the secretkey's encrypted contents.
     * 
     * @param passphrase
     * @param provider
     * @return pgpprivatekey
     * @throws pgpexception
     * @throws nosuchproviderexception
     * @deprecated use method that takes a pbesecretkeydecryptor
     */
    public  pgpprivatekey extractprivatekey(
        char[]                passphrase,
        string                provider)
        throws pgpexception, nosuchproviderexception
    {
        return extractprivatekey(passphrase, pgputil.getprovider(provider));
    }

    /**
     * extract a pgpprivate key from the secretkey's encrypted contents.
     *
     * @param passphrase
     * @param provider
     * @return pgpprivatekey
     * @throws pgpexception
     * @deprecated use method that takes a pbesecretkeydecryptor
     */
    public  pgpprivatekey extractprivatekey(
        char[]   passphrase,
        provider provider)
        throws pgpexception
    {
        return extractprivatekey(new jcepbesecretkeydecryptorbuilder(new jcapgpdigestcalculatorproviderbuilder().setprovider(provider).build()).setprovider(provider).build(passphrase));
    }

    /**
     * extract a pgpprivate key from the secretkey's encrypted contents.
     *
     * @param decryptorfactory  factory to use to generate a decryptor for the passed in secretkey.
     * @return pgpprivatekey  the unencrypted private key.
     * @throws pgpexception on failure.
     */
    public  pgpprivatekey extractprivatekey(
        pbesecretkeydecryptor decryptorfactory)
        throws pgpexception
    {
        if (isprivatekeyempty())
        {
            return null;
        }

        publickeypacket pubpk = secret.getpublickeypacket();

        try
        {
            byte[]             data = extractkeydata(decryptorfactory);
            bcpginputstream    in = new bcpginputstream(new bytearrayinputstream(data));


            switch (pubpk.getalgorithm())
            {
            case pgppublickey.rsa_encrypt:
            case pgppublickey.rsa_general:
            case pgppublickey.rsa_sign:
                rsasecretbcpgkey        rsapriv = new rsasecretbcpgkey(in);

                return new pgpprivatekey(this.getkeyid(), pubpk, rsapriv);
            case pgppublickey.dsa:
                dsasecretbcpgkey    dsapriv = new dsasecretbcpgkey(in);

                return new pgpprivatekey(this.getkeyid(), pubpk, dsapriv);
            case pgppublickey.elgamal_encrypt:
            case pgppublickey.elgamal_general:
                elgamalsecretbcpgkey    elpriv = new elgamalsecretbcpgkey(in);

                return new pgpprivatekey(this.getkeyid(), pubpk, elpriv);
            default:
                throw new pgpexception("unknown public key algorithm encountered");
            }
        }
        catch (pgpexception e)
        {
            throw e;
        }
        catch (exception e)
        {
            throw new pgpexception("exception constructing key", e);
        }
    }
    
    private static byte[] checksum(pgpdigestcalculator digcalc, byte[] bytes, int length)
        throws pgpexception
    {
        if (digcalc != null)
        {
            outputstream dout = digcalc.getoutputstream();

            try
            {
            dout.write(bytes, 0, length);

            dout.close();
            }
            catch (exception e)
            {
               throw new pgpexception("checksum digest calculation failed: " + e.getmessage(), e);
            }
            return digcalc.getdigest();
        }
        else
        {
            int       checksum = 0;
        
            for (int i = 0; i != length; i++)
            {
                checksum += bytes[i] & 0xff;
            }
        
            byte[] check = new byte[2];

            check[0] = (byte)(checksum >> 8);
            check[1] = (byte)checksum;

            return check;
        }
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

        out.writepacket(secret);
        if (pub.trustpk != null)
        {
            out.writepacket(pub.trustpk);
        }
        
        if (pub.subsigs == null)        // is not a sub key
        {
            for (int i = 0; i != pub.keysigs.size(); i++)
            {
                ((pgpsignature)pub.keysigs.get(i)).encode(out);
            }
            
            for (int i = 0; i != pub.ids.size(); i++)
            {
                if (pub.ids.get(i) instanceof string)
                {
                    string    id = (string)pub.ids.get(i);
                    
                    out.writepacket(new useridpacket(id));
                }
                else
                {
                    pgpuserattributesubpacketvector    v = (pgpuserattributesubpacketvector)pub.ids.get(i);

                    out.writepacket(new userattributepacket(v.tosubpacketarray()));
                }
                
                if (pub.idtrusts.get(i) != null)
                {
                    out.writepacket((containedpacket)pub.idtrusts.get(i));
                }
                
                list         sigs = (arraylist)pub.idsigs.get(i);
                
                for (int j = 0; j != sigs.size(); j++)
                {
                    ((pgpsignature)sigs.get(j)).encode(out);
                }
            }
        }
        else
        {        
            for (int j = 0; j != pub.subsigs.size(); j++)
            {
                ((pgpsignature)pub.subsigs.get(j)).encode(out);
            }
        }
    }

    /**
     * return a copy of the passed in secret key, encrypted using a new
     * password and the passed in algorithm.
     *
     * @param key the pgpsecretkey to be copied.
     * @param oldpassphrase the current password for key.
     * @param newpassphrase the new password for the key.
     * @param newencalgorithm the algorithm to be used for the encryption.
     * @param rand source of randomness.
     * @param provider name of the provider to use
     *  @deprecated use method taking pbesecretkeydecryptor and pbesecretkeyencryptor
     */
    public static pgpsecretkey copywithnewpassword(
        pgpsecretkey    key,
        char[]          oldpassphrase,
        char[]          newpassphrase,
        int             newencalgorithm,
        securerandom    rand,
        string          provider)
        throws pgpexception, nosuchproviderexception
    {
        return copywithnewpassword(key, oldpassphrase, newpassphrase, newencalgorithm, rand, pgputil.getprovider(provider));
    }

    /**
     * return a copy of the passed in secret key, encrypted using a new
     * password and the passed in algorithm.
     *
     * @param key the pgpsecretkey to be copied.
     * @param oldkeydecryptor the current decryptor based on the current password for key.
     * @param newkeyencryptor a new encryptor based on a new password for encrypting the secret key material.
     */
    public static pgpsecretkey copywithnewpassword(
        pgpsecretkey           key,
        pbesecretkeydecryptor  oldkeydecryptor,
        pbesecretkeyencryptor  newkeyencryptor)
        throws pgpexception
    {
        if (key.isprivatekeyempty())
        {
            throw new pgpexception("no private key in this secretkey - public key present only.");
        }

        byte[]     rawkeydata = key.extractkeydata(oldkeydecryptor);
        int        s2kusage = key.secret.gets2kusage();
        byte[]      iv = null;
        s2k         s2k = null;
        byte[]      keydata;
        int         newencalgorithm = symmetrickeyalgorithmtags.null;

        if (newkeyencryptor == null || newkeyencryptor.getalgorithm() == symmetrickeyalgorithmtags.null)
        {
            s2kusage = secretkeypacket.usage_none;
            if (key.secret.gets2kusage() == secretkeypacket.usage_sha1)   // sha-1 hash, need to rewrite checksum
            {
                keydata = new byte[rawkeydata.length - 18];

                system.arraycopy(rawkeydata, 0, keydata, 0, keydata.length - 2);

                byte[] check = checksum(null, keydata, keydata.length - 2);

                keydata[keydata.length - 2] = check[0];
                keydata[keydata.length - 1] = check[1];
            }
            else
            {
                keydata = rawkeydata;
            }
        }
        else
        {
            if (key.secret.getpublickeypacket().getversion() < 4)
            {
                // version 2 or 3 - rsa keys only

                byte[] enckey = newkeyencryptor.getkey();
                keydata = new byte[rawkeydata.length];

                if (newkeyencryptor.gethashalgorithm() != hashalgorithmtags.md5)
                {
                    throw new pgpexception("md5 digest calculator required for version 3 key encryptor.");
                }

                //
                // process 4 numbers
                //
                int pos = 0;
                for (int i = 0; i != 4; i++)
                {
                    int enclen = (((rawkeydata[pos] << 8) | (rawkeydata[pos + 1] & 0xff)) + 7) / 8;

                    keydata[pos] = rawkeydata[pos];
                    keydata[pos + 1] = rawkeydata[pos + 1];

                    byte[] tmp;
                    if (i == 0)
                    {
                        tmp = newkeyencryptor.encryptkeydata(enckey, rawkeydata, pos + 2, enclen);
                        iv = newkeyencryptor.getcipheriv();

                    }
                    else
                    {
                        byte[] tmpiv = new byte[iv.length];

                        system.arraycopy(keydata, pos - iv.length, tmpiv, 0, tmpiv.length);
                        tmp = newkeyencryptor.encryptkeydata(enckey, tmpiv, rawkeydata, pos + 2, enclen);
                    }

                    system.arraycopy(tmp, 0, keydata, pos + 2, tmp.length);
                    pos += 2 + enclen;
                }

                //
                // copy in checksum.
                //
                keydata[pos] = rawkeydata[pos];
                keydata[pos + 1] = rawkeydata[pos + 1];

                s2k = newkeyencryptor.gets2k();
                newencalgorithm = newkeyencryptor.getalgorithm();
            }
            else
            {
                keydata = newkeyencryptor.encryptkeydata(rawkeydata, 0, rawkeydata.length);

                iv = newkeyencryptor.getcipheriv();

                s2k = newkeyencryptor.gets2k();

                newencalgorithm = newkeyencryptor.getalgorithm();
            }
        }

        secretkeypacket             secret;
        if (key.secret instanceof secretsubkeypacket)
        {
            secret = new secretsubkeypacket(key.secret.getpublickeypacket(),
                newencalgorithm, s2kusage, s2k, iv, keydata);
        }
        else
        {
            secret = new secretkeypacket(key.secret.getpublickeypacket(),
                newencalgorithm, s2kusage, s2k, iv, keydata);
        }

        return new pgpsecretkey(secret, key.pub);
    }

    /**
     * return a copy of the passed in secret key, encrypted using a new
     * password and the passed in algorithm.
     *
     * @param key the pgpsecretkey to be copied.
     * @param oldpassphrase the current password for key.
     * @param newpassphrase the new password for the key.
     * @param newencalgorithm the algorithm to be used for the encryption.
     * @param rand source of randomness.
     * @param provider the provider to use
     * @deprecated use method taking pbesecretkeydecryptor and pbesecretkeyencryptor
     */
    public static pgpsecretkey copywithnewpassword(
        pgpsecretkey    key,
        char[]          oldpassphrase,
        char[]          newpassphrase,
        int             newencalgorithm,
        securerandom    rand,
        provider        provider)
        throws pgpexception
    {
        return copywithnewpassword(key, new jcepbesecretkeydecryptorbuilder(new jcapgpdigestcalculatorproviderbuilder().setprovider(provider).build()).setprovider(provider).build(oldpassphrase), new jcepbesecretkeyencryptorbuilder(newencalgorithm).setprovider(provider).setsecurerandom(rand).build(newpassphrase));
    }

    /**
     * replace the passed the public key on the passed in secret key.
     *
     * @param secretkey secret key to change
     * @param publickey new public key.
     * @return a new secret key.
     * @throws illegalargumentexception if keyids do not match.
     */
    public static pgpsecretkey replacepublickey(pgpsecretkey secretkey, pgppublickey publickey)
    {
        if (publickey.getkeyid() != secretkey.getkeyid())
        {
            throw new illegalargumentexception("keyids do not match");
        }

        return new pgpsecretkey(secretkey.secret, publickey);
    }
}
