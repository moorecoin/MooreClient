package org.ripple.bouncycastle.openpgp;

import java.io.ioexception;
import java.io.outputstream;
import java.security.nosuchproviderexception;
import java.security.provider;
import java.security.securerandom;
import java.util.arraylist;
import java.util.list;

import org.ripple.bouncycastle.bcpg.bcpgoutputstream;
import org.ripple.bouncycastle.bcpg.hashalgorithmtags;
import org.ripple.bouncycastle.bcpg.packettags;
import org.ripple.bouncycastle.bcpg.symmetrickeyalgorithmtags;
import org.ripple.bouncycastle.jce.provider.bouncycastleprovider;
import org.ripple.bouncycastle.openpgp.operator.pbekeyencryptionmethodgenerator;
import org.ripple.bouncycastle.openpgp.operator.pgpdataencryptor;
import org.ripple.bouncycastle.openpgp.operator.pgpdataencryptorbuilder;
import org.ripple.bouncycastle.openpgp.operator.pgpdigestcalculator;
import org.ripple.bouncycastle.openpgp.operator.pgpkeyencryptionmethodgenerator;
import org.ripple.bouncycastle.openpgp.operator.jcajce.jcapgpdigestcalculatorproviderbuilder;
import org.ripple.bouncycastle.openpgp.operator.jcajce.jcepbekeyencryptionmethodgenerator;
import org.ripple.bouncycastle.openpgp.operator.jcajce.jcepgpdataencryptorbuilder;
import org.ripple.bouncycastle.openpgp.operator.jcajce.jcepublickeykeyencryptionmethodgenerator;
import org.ripple.bouncycastle.util.io.teeoutputstream;

/**
 *  generator for encrypted objects.
 */
public class pgpencrypteddatagenerator
    implements symmetrickeyalgorithmtags, streamgenerator
{
    /**
     * specifier for sha-1 s2k pbe generator.
     */
    public static final int s2k_sha1 = hashalgorithmtags.sha1;

    /**
     * specifier for sha-224 s2k pbe generator.
     */
    public static final int s2k_sha224 = hashalgorithmtags.sha224;

    /**
     * specifier for sha-256 s2k pbe generator.
     */
    public static final int s2k_sha256 = hashalgorithmtags.sha256;

    /**
     * specifier for sha-384 s2k pbe generator.
     */
    public static final int s2k_sha384 = hashalgorithmtags.sha384;

    /**
     * specifier for sha-512 s2k pbe generator.
     */
    public static final int s2k_sha512 = hashalgorithmtags.sha512;

    private bcpgoutputstream     pout;
    private outputstream         cout;
    private boolean              oldformat = false;
    private pgpdigestcalculator digestcalc;
    private outputstream            genout;
    private pgpdataencryptorbuilder dataencryptorbuilder;

    private list            methods = new arraylist();
    private int             defalgorithm;
    private securerandom    rand;

    private static provider        defprovider;
    
   /**
       * base constructor.
       *
       * @param encalgorithm the symmetric algorithm to use.
       * @param rand source of randomness
       * @param provider the provider name to use for encryption algorithms.
       * @deprecated  use constructor that takes a pgpdataencryptor
       */
    public pgpencrypteddatagenerator(
        int                 encalgorithm,
        securerandom        rand,
        string              provider)
    {
        this(new jcepgpdataencryptorbuilder(encalgorithm).setsecurerandom(rand).setprovider(provider));
    }

   /**
       * base constructor.
       *
       * @param encalgorithm the symmetric algorithm to use.
       * @param rand source of randomness
       * @param provider the provider to use for encryption algorithms.
       * @deprecated  use constructor that takes a pgpdataencryptorbuilder
       */
    public pgpencrypteddatagenerator(
        int                 encalgorithm,
        securerandom        rand,
        provider            provider)
    {
        this(new jcepgpdataencryptorbuilder(encalgorithm).setsecurerandom(rand).setprovider(provider));
    }

    /**
        * creates a cipher stream which will have an integrity packet
        * associated with it.
        *
        * @param encalgorithm
        * @param withintegritypacket
        * @param rand
        * @param provider
        * @deprecated  use constructor that takes a pgpdataencryptorbuilder
        */
    public pgpencrypteddatagenerator(
        int                 encalgorithm,
        boolean             withintegritypacket,
        securerandom        rand,
        string              provider)
    {
        this(new jcepgpdataencryptorbuilder(encalgorithm).setwithintegritypacket(withintegritypacket).setsecurerandom(rand).setprovider(provider));
    }

    /**
        * creates a cipher stream which will have an integrity packet
        * associated with it.
        *
        * @param encalgorithm
        * @param withintegritypacket
        * @param rand
        * @param provider
        * @deprecated  use constructor that takes a pgpdataencryptorbuilder
        */
    public pgpencrypteddatagenerator(
        int                 encalgorithm,
        boolean             withintegritypacket,
        securerandom        rand,
        provider            provider)
    {
        this(new jcepgpdataencryptorbuilder(encalgorithm).setwithintegritypacket(withintegritypacket).setsecurerandom(rand).setprovider(provider));
    }

   /**
       * base constructor.
       *
       * @param encalgorithm the symmetric algorithm to use.
       * @param rand source of randomness
       * @param oldformat pgp 2.6.x compatibility required.
       * @param provider the provider to use for encryption algorithms.
       * @deprecated  use constructor that takes a pgpdataencryptorbuilder
       */
    public pgpencrypteddatagenerator(
        int                 encalgorithm,
        securerandom        rand,
        boolean             oldformat,
        string              provider)
    {
        this(new jcepgpdataencryptorbuilder(encalgorithm).setsecurerandom(rand).setprovider(provider), oldformat);
    }

   /**
       * base constructor.
       *
       * @param encalgorithm the symmetric algorithm to use.
       * @param rand source of randomness
       * @param oldformat pgp 2.6.x compatibility required.
       * @param provider the provider to use for encryption algorithms.
       * @deprecated  use constructor that takes a pgpdataencryptorbuilder
       */
    public pgpencrypteddatagenerator(
        int                 encalgorithm,
        securerandom        rand,
        boolean             oldformat,
        provider            provider)
    {
        this(new jcepgpdataencryptorbuilder(encalgorithm).setsecurerandom(rand).setprovider(provider), oldformat);
    }

   /**
       * base constructor.
       *
       * @param encryptorbuilder builder to create actual data encryptor.
       */
    public pgpencrypteddatagenerator(pgpdataencryptorbuilder encryptorbuilder)
    {
        this(encryptorbuilder, false);
    }

   /**
       * base constructor with the option to turn on formatting for pgp 2.6.x compatibility.
       *
       * @param encryptorbuilder builder to create actual data encryptor.
       * @param oldformat pgp 2.6.x compatibility required.
       */
    public pgpencrypteddatagenerator(pgpdataencryptorbuilder encryptorbuilder, boolean oldformat)
    {
        this.dataencryptorbuilder = encryptorbuilder;
        this.oldformat = oldformat;

        this.defalgorithm = dataencryptorbuilder.getalgorithm();
        this.rand = dataencryptorbuilder.getsecurerandom();
    }

    /**
     * add a pbe encryption method to the encrypted object using the default algorithm (s2k_sha1).
     * 
     * @param passphrase
     * @throws nosuchproviderexception
     * @throws pgpexception
     * @deprecated  use addmethod that takes  pgpkeyencryptionmethodgenerator
     */
    public void addmethod(
        char[]    passphrase) 
        throws nosuchproviderexception, pgpexception
    {
        addmethod(passphrase, hashalgorithmtags.sha1);
    }

    /**
     * add a pbe encryption method to the encrypted object.
     *
     * @param passphrase passphrase to use to generate key.
     * @param s2kdigest digest algorithm to use for s2k calculation
     * @throws nosuchproviderexception
     * @throws pgpexception
     * @deprecated  use addmethod that takes  pgpkeyencryptionmethodgenerator
     */
    public void addmethod(
        char[]    passphrase,
        int       s2kdigest)
        throws nosuchproviderexception, pgpexception
    {
        if (defprovider == null)
        {
            defprovider = new bouncycastleprovider();
        }

        addmethod(new jcepbekeyencryptionmethodgenerator(passphrase, new jcapgpdigestcalculatorproviderbuilder().setprovider(defprovider).build().get(s2kdigest)).setprovider(defprovider).setsecurerandom(rand));
    }

    /**
     * add a public key encrypted session key to the encrypted object.
     * 
     * @param key
     * @throws nosuchproviderexception
     * @throws pgpexception
     * @deprecated  use addmethod that takes  pgpkeyencryptionmethodgenerator
     */
    public void addmethod(
        pgppublickey    key) 
        throws nosuchproviderexception, pgpexception
    {   
        if (!key.isencryptionkey())
        {
            throw new illegalargumentexception("passed in key not an encryption key!");
        }

        if (defprovider == null)
        {
            defprovider = new bouncycastleprovider();
        }

        addmethod(new jcepublickeykeyencryptionmethodgenerator(key).setprovider(defprovider).setsecurerandom(rand));
    }

    /**
        *  added a key encryption method to be used to encrypt the session data associated
        *  with this encrypted data.
        *
        * @param method  key encryption method to use.
        */
    public void addmethod(pgpkeyencryptionmethodgenerator method)
    {
        methods.add(method);
    }

    private void addchecksum(
        byte[]    sessioninfo)
    {
        int    check = 0;
        
        for (int i = 1; i != sessioninfo.length - 2; i++)
        {
            check += sessioninfo[i] & 0xff;
        }
        
        sessioninfo[sessioninfo.length - 2] = (byte)(check >> 8);
        sessioninfo[sessioninfo.length - 1] = (byte)(check);
    }

    private byte[] createsessioninfo(
        int     algorithm,
        byte[]  keybytes)
    {
        byte[] sessioninfo = new byte[keybytes.length + 3];
        sessioninfo[0] = (byte) algorithm;
        system.arraycopy(keybytes, 0, sessioninfo, 1, keybytes.length);
        addchecksum(sessioninfo);
        return sessioninfo;
    }

    /**
     * if buffer is non null stream assumed to be partial, otherwise the
     * length will be used to output a fixed length packet.
     * <p>
     * the stream created can be closed off by either calling close()
     * on the stream or close() on the generator. closing the returned
     * stream does not close off the outputstream parameter out.
     * 
     * @param out
     * @param length
     * @param buffer
     * @return
     * @throws java.io.ioexception
     * @throws pgpexception
     * @throws illegalstateexception
     */
    private outputstream open(
        outputstream    out,
        long            length,
        byte[]          buffer)
        throws ioexception, pgpexception, illegalstateexception
    {
        if (cout != null)
        {
            throw new illegalstateexception("generator already in open state");
        }

        if (methods.size() == 0)
        {
            throw new illegalstateexception("no encryption methods specified");
        }

        byte[] key = null;

        pout = new bcpgoutputstream(out);

        defalgorithm = dataencryptorbuilder.getalgorithm();
        rand = dataencryptorbuilder.getsecurerandom();

        if (methods.size() == 1)
        {    

            if (methods.get(0) instanceof pbekeyencryptionmethodgenerator)
            {
                pbekeyencryptionmethodgenerator m = (pbekeyencryptionmethodgenerator)methods.get(0);

                key = m.getkey(dataencryptorbuilder.getalgorithm());

                pout.writepacket(((pgpkeyencryptionmethodgenerator)methods.get(0)).generate(defalgorithm, null));
            }
            else
            {
                key = pgputil.makerandomkey(defalgorithm, rand);
                byte[] sessioninfo = createsessioninfo(defalgorithm, key);
                pgpkeyencryptionmethodgenerator m = (pgpkeyencryptionmethodgenerator)methods.get(0);

                pout.writepacket(m.generate(defalgorithm, sessioninfo));
            }
        }
        else // multiple methods
        {
            key = pgputil.makerandomkey(defalgorithm, rand);
            byte[] sessioninfo = createsessioninfo(defalgorithm, key);

            for (int i = 0; i != methods.size(); i++)
            {
                pgpkeyencryptionmethodgenerator m = (pgpkeyencryptionmethodgenerator)methods.get(i);

                pout.writepacket(m.generate(defalgorithm, sessioninfo));
            }
        }

        try
        {
            pgpdataencryptor dataencryptor = dataencryptorbuilder.build(key);

            digestcalc = dataencryptor.getintegritycalculator();
            
            if (buffer == null)
            {
                //
                // we have to add block size + 2 for the generated iv and + 1 + 22 if integrity protected
                //
                if (digestcalc != null)
                {
                    pout = new closablebcpgoutputstream(out, packettags.sym_enc_integrity_pro, length + dataencryptor.getblocksize() + 2 + 1 + 22);

                    pout.write(1);        // version number
                }
                else
                {
                    pout = new closablebcpgoutputstream(out, packettags.symmetric_key_enc, length + dataencryptor.getblocksize() + 2, oldformat);
                }
            }
            else
            {
                if (digestcalc != null)
                {
                    pout = new closablebcpgoutputstream(out, packettags.sym_enc_integrity_pro, buffer);
                    pout.write(1);        // version number
                }
                else
                {
                    pout = new closablebcpgoutputstream(out, packettags.symmetric_key_enc, buffer);
                }
            }

            genout = cout = dataencryptor.getoutputstream(pout);

            if (digestcalc != null)
            {
                genout = new teeoutputstream(digestcalc.getoutputstream(), cout);
            }

            byte[] inlineiv = new byte[dataencryptor.getblocksize() + 2];
            rand.nextbytes(inlineiv);
            inlineiv[inlineiv.length - 1] = inlineiv[inlineiv.length - 3];
            inlineiv[inlineiv.length - 2] = inlineiv[inlineiv.length - 4];

            genout.write(inlineiv);

            return new wrappedgeneratorstream(genout, this);
        }
        catch (exception e)
        {
            throw new pgpexception("exception creating cipher", e);
        }
    }

    /**
     * return an outputstream which will encrypt the data as it is written
     * to it.
     * <p>
     * the stream created can be closed off by either calling close()
     * on the stream or close() on the generator. closing the returned
     * stream does not close off the outputstream parameter out.
     * 
     * @param out
     * @param length
     * @return outputstream
     * @throws ioexception
     * @throws pgpexception
     */
    public outputstream open(
        outputstream    out,
        long            length)
        throws ioexception, pgpexception
    {
        return this.open(out, length, null);
    }
    
    /**
     * return an outputstream which will encrypt the data as it is written
     * to it. the stream will be written out in chunks according to the size of the
     * passed in buffer.
     * <p>
     * the stream created can be closed off by either calling close()
     * on the stream or close() on the generator. closing the returned
     * stream does not close off the outputstream parameter out.
     * <p>
     * <b>note</b>: if the buffer is not a power of 2 in length only the largest power of 2
     * bytes worth of the buffer will be used.
     * 
     * @param out
     * @param buffer the buffer to use.
     * @return outputstream
     * @throws ioexception
     * @throws pgpexception
     */
    public outputstream open(
        outputstream    out,
        byte[]          buffer)
        throws ioexception, pgpexception
    {
        return this.open(out, 0, buffer);
    }
    
    /**
     * close off the encrypted object - this is equivalent to calling close on the stream
     * returned by the open() method.
     * <p>
     * <b>note</b>: this does not close the underlying output stream, only the stream on top of it created by the open() method.
     * @throws java.io.ioexception
     */
    public void close()
        throws ioexception
    {
        if (cout != null)
        {    
            if (digestcalc != null)
            {
                //
                // hand code a mod detection packet
                //
                bcpgoutputstream bout = new bcpgoutputstream(genout, packettags.mod_detection_code, 20);

                bout.flush();

                byte[] dig = digestcalc.getdigest();

                cout.write(dig);
            }

            cout.close();

            cout = null;
            pout = null;
        }
    }

    private class closablebcpgoutputstream
        extends bcpgoutputstream
    {
        public closablebcpgoutputstream(outputstream out, int symmetrickeyenc, byte[] buffer)
            throws ioexception
        {
            super(out, symmetrickeyenc, buffer);
        }

        public closablebcpgoutputstream(outputstream out, int symmetrickeyenc, long length, boolean oldformat)
            throws ioexception
        {
            super(out, symmetrickeyenc, length, oldformat);
        }

        public closablebcpgoutputstream(outputstream out, int symencintegritypro, long length)
            throws ioexception
        {
            super(out, symencintegritypro, length);
        }

        public void close()
            throws ioexception
        {
             this.finish();
        }
    }
}
