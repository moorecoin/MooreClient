package org.ripple.bouncycastle.jcajce.provider.keystore.bc;

import java.io.bytearrayinputstream;
import java.io.bytearrayoutputstream;
import java.io.datainputstream;
import java.io.dataoutputstream;
import java.io.ioexception;
import java.io.inputstream;
import java.io.outputstream;
import java.security.key;
import java.security.keyfactory;
import java.security.keystoreexception;
import java.security.keystorespi;
import java.security.nosuchalgorithmexception;
import java.security.nosuchproviderexception;
import java.security.privatekey;
import java.security.publickey;
import java.security.securerandom;
import java.security.unrecoverablekeyexception;
import java.security.cert.certificate;
import java.security.cert.certificateencodingexception;
import java.security.cert.certificateexception;
import java.security.cert.certificatefactory;
import java.security.spec.keyspec;
import java.security.spec.pkcs8encodedkeyspec;
import java.security.spec.x509encodedkeyspec;
import java.util.date;
import java.util.enumeration;
import java.util.hashtable;

import javax.crypto.cipher;
import javax.crypto.cipherinputstream;
import javax.crypto.cipheroutputstream;
import javax.crypto.secretkeyfactory;
import javax.crypto.spec.pbekeyspec;
import javax.crypto.spec.pbeparameterspec;
import javax.crypto.spec.secretkeyspec;

import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.crypto.pbeparametersgenerator;
import org.ripple.bouncycastle.crypto.digests.sha1digest;
import org.ripple.bouncycastle.crypto.generators.pkcs12parametersgenerator;
import org.ripple.bouncycastle.crypto.io.digestinputstream;
import org.ripple.bouncycastle.crypto.io.digestoutputstream;
import org.ripple.bouncycastle.crypto.io.macinputstream;
import org.ripple.bouncycastle.crypto.io.macoutputstream;
import org.ripple.bouncycastle.crypto.macs.hmac;
import org.ripple.bouncycastle.jce.interfaces.bckeystore;
import org.ripple.bouncycastle.jce.provider.bouncycastleprovider;
import org.ripple.bouncycastle.util.arrays;
import org.ripple.bouncycastle.util.io.streams;
import org.ripple.bouncycastle.util.io.teeoutputstream;

public class bckeystorespi
    extends keystorespi
    implements bckeystore
{
    private static final int    store_version = 2;

    private static final int    store_salt_size = 20;
    private static final string store_cipher = "pbewithshaandtwofish-cbc";

    private static final int    key_salt_size = 20;
    private static final int    min_iterations = 1024;

    private static final string key_cipher = "pbewithshaand3-keytripledes-cbc";

    //
    // generic object types
    //
    static final int null           = 0;
    static final int certificate    = 1;
    static final int key            = 2;
    static final int secret         = 3;
    static final int sealed         = 4;

    //
    // key types
    //
    static final int    key_private = 0;
    static final int    key_public  = 1;
    static final int    key_secret  = 2;

    protected hashtable       table = new hashtable();

    protected securerandom    random = new securerandom();

    protected int              version;

    public bckeystorespi(int version)
    {
        this.version = version;
    }

    private class storeentry
    {
        int             type;
        string          alias;
        object          obj;
        certificate[]   certchain;
        date            date = new date();

        storeentry(
            string       alias,
            certificate  obj)
        {
            this.type = certificate;
            this.alias = alias;
            this.obj = obj;
            this.certchain = null;
        }

        storeentry(
            string          alias,
            byte[]          obj,
            certificate[]   certchain)
        {
            this.type = secret;
            this.alias = alias;
            this.obj = obj;
            this.certchain = certchain;
        }

        storeentry(
            string          alias,
            key             key,
            char[]          password,
            certificate[]   certchain)
            throws exception
        {
            this.type = sealed;
            this.alias = alias;
            this.certchain = certchain;

            byte[] salt = new byte[key_salt_size];

            random.setseed(system.currenttimemillis());
            random.nextbytes(salt);

            int iterationcount = min_iterations + (random.nextint() & 0x3ff);


            bytearrayoutputstream   bout = new bytearrayoutputstream();
            dataoutputstream        dout = new dataoutputstream(bout);

            dout.writeint(salt.length);
            dout.write(salt);
            dout.writeint(iterationcount);

            cipher              cipher = makepbecipher(key_cipher, cipher.encrypt_mode, password, salt, iterationcount);
            cipheroutputstream  cout = new cipheroutputstream(dout, cipher);

            dout = new dataoutputstream(cout);

            encodekey(key, dout);

            dout.close();

            obj = bout.tobytearray();
        }

        storeentry(
            string          alias,
            date            date,
            int             type,
            object          obj)
        {
            this.alias = alias;
            this.date = date;
            this.type = type;
            this.obj = obj;
        }

        storeentry(
            string          alias,
            date            date,
            int             type,
            object          obj,
            certificate[]   certchain)
        {
            this.alias = alias;
            this.date = date;
            this.type = type;
            this.obj = obj;
            this.certchain = certchain;
        }

        int gettype()
        {
            return type;
        }

        string getalias()
        {
            return alias;
        }

        object getobject()
        {
            return obj;
        }

        object getobject(
            char[]  password)
            throws nosuchalgorithmexception, unrecoverablekeyexception
        {
            if (password == null || password.length == 0)
            {
                if (obj instanceof key)
                {
                    return obj;
                }
            }

            if (type == sealed)
            {
                bytearrayinputstream    bin = new bytearrayinputstream((byte[])obj);
                datainputstream         din = new datainputstream(bin);
            
                try
                {
                    byte[]      salt = new byte[din.readint()];

                    din.readfully(salt);

                    int     iterationcount = din.readint();
                
                    cipher      cipher = makepbecipher(key_cipher, cipher.decrypt_mode, password, salt, iterationcount);

                    cipherinputstream cin = new cipherinputstream(din, cipher);

                    try
                    {
                        return decodekey(new datainputstream(cin));
                    }
                    catch (exception x)
                    {
                        bin = new bytearrayinputstream((byte[])obj);
                        din = new datainputstream(bin);
            
                        salt = new byte[din.readint()];

                        din.readfully(salt);

                        iterationcount = din.readint();

                        cipher = makepbecipher("broken" + key_cipher, cipher.decrypt_mode, password, salt, iterationcount);

                        cin = new cipherinputstream(din, cipher);

                        key k = null;

                        try
                        {
                            k = decodekey(new datainputstream(cin));
                        }
                        catch (exception y)
                        {
                            bin = new bytearrayinputstream((byte[])obj);
                            din = new datainputstream(bin);
                
                            salt = new byte[din.readint()];

                            din.readfully(salt);

                            iterationcount = din.readint();

                            cipher = makepbecipher("old" + key_cipher, cipher.decrypt_mode, password, salt, iterationcount);

                            cin = new cipherinputstream(din, cipher);

                            k = decodekey(new datainputstream(cin));
                        }

                        //
                        // reencrypt key with correct cipher.
                        //
                        if (k != null)
                        {
                            bytearrayoutputstream   bout = new bytearrayoutputstream();
                            dataoutputstream        dout = new dataoutputstream(bout);

                            dout.writeint(salt.length);
                            dout.write(salt);
                            dout.writeint(iterationcount);

                            cipher              out = makepbecipher(key_cipher, cipher.encrypt_mode, password, salt, iterationcount);
                            cipheroutputstream  cout = new cipheroutputstream(dout, out);

                            dout = new dataoutputstream(cout);

                            encodekey(k, dout);

                            dout.close();

                            obj = bout.tobytearray();

                            return k;
                        }
                        else
                        {
                            throw new unrecoverablekeyexception("no match");
                        }
                    }
                }
                catch (exception e)
                {
                    throw new unrecoverablekeyexception("no match");
                }
            }
            else
            {
                throw new runtimeexception("forget something!");
                // todo
                // if we get to here key was saved as byte data, which
                // according to the docs means it must be a private key
                // in encryptedprivatekeyinfo (pkcs8 format), later...
                //
            }
        }

        certificate[] getcertificatechain()
        {
            return certchain;
        }

        date getdate()
        {
            return date;
        }
    }

    private void encodecertificate(
        certificate         cert,
        dataoutputstream    dout)
        throws ioexception
    {
        try
        {
            byte[]      cenc = cert.getencoded();

            dout.writeutf(cert.gettype());
            dout.writeint(cenc.length);
            dout.write(cenc);
        }
        catch (certificateencodingexception ex)
        {
            throw new ioexception(ex.tostring());
        }
    }

    private certificate decodecertificate(
        datainputstream   din)
        throws ioexception
    {
        string      type = din.readutf();
        byte[]      cenc = new byte[din.readint()];

        din.readfully(cenc);

        try
        {
            certificatefactory cfact = certificatefactory.getinstance(type, bouncycastleprovider.provider_name);
            bytearrayinputstream bin = new bytearrayinputstream(cenc);

            return cfact.generatecertificate(bin);
        }
        catch (nosuchproviderexception ex)
        {
            throw new ioexception(ex.tostring());
        }
        catch (certificateexception ex)
        {
            throw new ioexception(ex.tostring());
        }
    }

    private void encodekey(
        key                 key,
        dataoutputstream    dout)
        throws ioexception
    {
        byte[]      enc = key.getencoded();

        if (key instanceof privatekey)
        {
            dout.write(key_private);
        }
        else if (key instanceof publickey)
        {
            dout.write(key_public);
        }
        else
        {
            dout.write(key_secret);
        }
    
        dout.writeutf(key.getformat());
        dout.writeutf(key.getalgorithm());
        dout.writeint(enc.length);
        dout.write(enc);
    }

    private key decodekey(
        datainputstream din)
        throws ioexception
    {
        int         keytype = din.read();
        string      format = din.readutf();
        string      algorithm = din.readutf();
        byte[]      enc = new byte[din.readint()];
        keyspec     spec;

        din.readfully(enc);

        if (format.equals("pkcs#8") || format.equals("pkcs8"))
        {
            spec = new pkcs8encodedkeyspec(enc);
        }
        else if (format.equals("x.509") || format.equals("x509"))
        {
            spec = new x509encodedkeyspec(enc);
        }
        else if (format.equals("raw"))
        {
            return new secretkeyspec(enc, algorithm);
        }
        else
        {
            throw new ioexception("key format " + format + " not recognised!");
        }

        try
        {
            switch (keytype)
            {
            case key_private:
                return keyfactory.getinstance(algorithm, bouncycastleprovider.provider_name).generateprivate(spec);
            case key_public:
                return keyfactory.getinstance(algorithm, bouncycastleprovider.provider_name).generatepublic(spec);
            case key_secret:
                return secretkeyfactory.getinstance(algorithm, bouncycastleprovider.provider_name).generatesecret(spec);
            default:
                throw new ioexception("key type " + keytype + " not recognised!");
            }
        }
        catch (exception e)
        {
            throw new ioexception("exception creating key: " + e.tostring());
        }
    }

    protected cipher makepbecipher(
        string  algorithm,
        int     mode,
        char[]  password,
        byte[]  salt,
        int     iterationcount)
        throws ioexception
    {
        try
        {
            pbekeyspec          pbespec = new pbekeyspec(password);
            secretkeyfactory    keyfact = secretkeyfactory.getinstance(algorithm, bouncycastleprovider.provider_name);
            pbeparameterspec    defparams = new pbeparameterspec(salt, iterationcount);

            cipher cipher = cipher.getinstance(algorithm, bouncycastleprovider.provider_name);

            cipher.init(mode, keyfact.generatesecret(pbespec), defparams);

            return cipher;
        }
        catch (exception e)
        {
            throw new ioexception("error initialising store of key store: " + e);
        }
    }

    public void setrandom(
            securerandom    rand)
    {
        this.random = rand;
    }

    public enumeration enginealiases() 
    {
        return table.keys();
    }

    public boolean enginecontainsalias(
        string  alias) 
    {
        return (table.get(alias) != null);
    }

    public void enginedeleteentry(
        string  alias) 
        throws keystoreexception
    {
        object  entry = table.get(alias);

        if (entry == null)
        {
            return;
        }

        table.remove(alias);
    }

    public certificate enginegetcertificate(
        string alias) 
    {
        storeentry  entry = (storeentry)table.get(alias);

        if (entry != null)
        {
            if (entry.gettype() == certificate)
            {
                return (certificate)entry.getobject();
            }
            else
            {
                certificate[]   chain = entry.getcertificatechain();

                if (chain != null)
                {
                    return chain[0];
                }
            }
        }

        return null;
    }

    public string enginegetcertificatealias(
        certificate cert) 
    {
        enumeration e = table.elements();
        while (e.hasmoreelements())
        {
            storeentry  entry = (storeentry)e.nextelement();

            if (entry.getobject() instanceof certificate)
            {
                certificate c = (certificate)entry.getobject();

                if (c.equals(cert))
                {
                    return entry.getalias();
                }
            }
            else
            {
                certificate[]   chain = entry.getcertificatechain();

                if (chain != null && chain[0].equals(cert))
                {
                    return entry.getalias();
                }
            }
        }

        return null;
    }
    
    public certificate[] enginegetcertificatechain(
        string alias) 
    {
        storeentry  entry = (storeentry)table.get(alias);

        if (entry != null)
        {
            return entry.getcertificatechain();
        }

        return null;
    }
    
    public date enginegetcreationdate(string alias) 
    {
        storeentry  entry = (storeentry)table.get(alias);

        if (entry != null)
        {
            return entry.getdate();
        }

        return null;
    }

    public key enginegetkey(
        string alias,
        char[] password) 
        throws nosuchalgorithmexception, unrecoverablekeyexception
    {
        storeentry  entry = (storeentry)table.get(alias);

        if (entry == null || entry.gettype() == certificate)
        {
            return null;
        }

        return (key)entry.getobject(password);
    }

    public boolean engineiscertificateentry(
        string alias) 
    {
        storeentry  entry = (storeentry)table.get(alias);

        if (entry != null && entry.gettype() == certificate)
        {
            return true;
        }
    
        return false;
    }

    public boolean engineiskeyentry(
        string alias) 
    {
        storeentry  entry = (storeentry)table.get(alias);

        if (entry != null && entry.gettype() != certificate)
        {
            return true;
        }
    
        return false;
    }

    public void enginesetcertificateentry(
        string      alias,
        certificate cert) 
        throws keystoreexception
    {
        storeentry  entry = (storeentry)table.get(alias);

        if (entry != null && entry.gettype() != certificate)
        {
            throw new keystoreexception("key store already has a key entry with alias " + alias);
        }

        table.put(alias, new storeentry(alias, cert));
    }

    public void enginesetkeyentry(
        string alias,
        byte[] key,
        certificate[] chain) 
        throws keystoreexception
    {
        table.put(alias, new storeentry(alias, key, chain));
    }

    public void enginesetkeyentry(
        string          alias,
        key             key,
        char[]          password,
        certificate[]   chain) 
        throws keystoreexception
    {
        if ((key instanceof privatekey) && (chain == null))
        {
            throw new keystoreexception("no certificate chain for private key");
        }

        try
        {
            table.put(alias, new storeentry(alias, key, password, chain));
        }
        catch (exception e)
        {
            throw new keystoreexception(e.tostring());
        }
    }

    public int enginesize() 
    {
        return table.size();
    }

    protected void loadstore(
        inputstream in)
        throws ioexception
    {
        datainputstream     din = new datainputstream(in);
        int                 type = din.read();

        while (type > null)
        {
            string          alias = din.readutf();
            date            date = new date(din.readlong());
            int             chainlength = din.readint();
            certificate[]   chain = null;

            if (chainlength != 0)
            {
                chain = new certificate[chainlength];

                for (int i = 0; i != chainlength; i++)
                {
                    chain[i] = decodecertificate(din);
                }
            }

            switch (type)
            {
            case certificate:
                    certificate     cert = decodecertificate(din);

                    table.put(alias, new storeentry(alias, date, certificate, cert));
                    break;
            case key:
                    key     key = decodekey(din);
                    table.put(alias, new storeentry(alias, date, key, key, chain));
                    break;
            case secret:
            case sealed:
                    byte[]      b = new byte[din.readint()];

                    din.readfully(b);
                    table.put(alias, new storeentry(alias, date, type, b, chain));
                    break;
            default:
                    throw new runtimeexception("unknown object type in store.");
            }

            type = din.read();
        }
    }

    protected void savestore(
        outputstream    out)
        throws ioexception
    {
        enumeration         e = table.elements();
        dataoutputstream    dout = new dataoutputstream(out);

        while (e.hasmoreelements())
        {
            storeentry  entry = (storeentry)e.nextelement();

            dout.write(entry.gettype());
            dout.writeutf(entry.getalias());
            dout.writelong(entry.getdate().gettime());

            certificate[]   chain = entry.getcertificatechain();
            if (chain == null)
            {
                dout.writeint(0);
            }
            else
            {
                dout.writeint(chain.length);
                for (int i = 0; i != chain.length; i++)
                {
                    encodecertificate(chain[i], dout);
                }
            }

            switch (entry.gettype())
            {
            case certificate:
                    encodecertificate((certificate)entry.getobject(), dout);
                    break;
            case key:
                    encodekey((key)entry.getobject(), dout);
                    break;
            case sealed:
            case secret:
                    byte[]  b = (byte[])entry.getobject();

                    dout.writeint(b.length);
                    dout.write(b);
                    break;
            default:
                    throw new runtimeexception("unknown object type in store.");
            }
        }

        dout.write(null);
    }

    public void engineload(
        inputstream stream,
        char[]      password) 
        throws ioexception
    {
        table.clear();

        if (stream == null)     // just initialising
        {
            return;
        }

        datainputstream     din = new datainputstream(stream);
        int                 version = din.readint();

        if (version != store_version)
        {
            if (version != 0 && version != 1)
            {
                throw new ioexception("wrong version of key store.");
            }
        }

        int saltlength = din.readint();
        if (saltlength <= 0)
        {
            throw new ioexception("invalid salt detected");
        }

        byte[]      salt = new byte[saltlength];

        din.readfully(salt);

        int         iterationcount = din.readint();

        //
        // we only do an integrity check if the password is provided.
        //
        hmac hmac = new hmac(new sha1digest());
        if (password != null && password.length != 0)
        {
            byte[] passkey = pbeparametersgenerator.pkcs12passwordtobytes(password);

            pbeparametersgenerator pbegen = new pkcs12parametersgenerator(new sha1digest());
            pbegen.init(passkey, salt, iterationcount);

            cipherparameters macparams;

            if (version != 2)
            {
                macparams = pbegen.generatederivedmacparameters(hmac.getmacsize());
            }
            else
            {
                macparams = pbegen.generatederivedmacparameters(hmac.getmacsize() * 8);
            }

            arrays.fill(passkey, (byte)0);

            hmac.init(macparams);
            macinputstream min = new macinputstream(din, hmac);

            loadstore(min);

            // finalise our mac calculation
            byte[] mac = new byte[hmac.getmacsize()];
            hmac.dofinal(mac, 0);

            // todo should this actually be reading the remainder of the stream?
            // read the original mac from the stream
            byte[] oldmac = new byte[hmac.getmacsize()];
            din.readfully(oldmac);

            if (!arrays.constanttimeareequal(mac, oldmac))
            {
                table.clear();
                throw new ioexception("keystore integrity check failed.");
            }
        }
        else
        {
            loadstore(din);

            // todo should this actually be reading the remainder of the stream?
            // parse the original mac from the stream too
            byte[] oldmac = new byte[hmac.getmacsize()];
            din.readfully(oldmac);
        }
    }


    public void enginestore(outputstream stream, char[] password) 
        throws ioexception
    {
        dataoutputstream    dout = new dataoutputstream(stream);
        byte[]              salt = new byte[store_salt_size];
        int                 iterationcount = min_iterations + (random.nextint() & 0x3ff);

        random.nextbytes(salt);

        dout.writeint(version);
        dout.writeint(salt.length);
        dout.write(salt);
        dout.writeint(iterationcount);

        hmac                    hmac = new hmac(new sha1digest());
        macoutputstream         mout = new macoutputstream(hmac);
        pbeparametersgenerator  pbegen = new pkcs12parametersgenerator(new sha1digest());
        byte[]                  passkey = pbeparametersgenerator.pkcs12passwordtobytes(password);

        pbegen.init(passkey, salt, iterationcount);

        if (version < 2)
        {
            hmac.init(pbegen.generatederivedmacparameters(hmac.getmacsize()));
        }
        else
        {
            hmac.init(pbegen.generatederivedmacparameters(hmac.getmacsize() * 8));
        }

        for (int i = 0; i != passkey.length; i++)
        {
            passkey[i] = 0;
        }

        savestore(new teeoutputstream(dout, mout));

        byte[]  mac = new byte[hmac.getmacsize()];

        hmac.dofinal(mac, 0);

        dout.write(mac);

        dout.close();
    }

    /**
     * the bouncycastle store. this wont work with the key tool as the
     * store is stored encrypted on disk, so the password is mandatory,
     * however if you hard drive is in a bad part of town and you absolutely,
     * positively, don't want nobody peeking at your things, this is the
     * one to use, no problem! after all in a bouncy castle nothing can
     * touch you.
     *
     * also referred to by the alias uber.
     */
    public static class bouncycastlestore
        extends bckeystorespi
    {
        public bouncycastlestore()
        {
            super(1);
        }

        public void engineload(
            inputstream stream,
            char[]      password) 
            throws ioexception
        {
            table.clear();
    
            if (stream == null)     // just initialising
            {
                return;
            }
    
            datainputstream     din = new datainputstream(stream);
            int                 version = din.readint();
    
            if (version != store_version)
            {
                if (version != 0 && version != 1)
                {
                    throw new ioexception("wrong version of key store.");
                }
            }
    
            byte[]      salt = new byte[din.readint()];

            if (salt.length != store_salt_size)
            {
                throw new ioexception("key store corrupted.");
            }
    
            din.readfully(salt);
    
            int         iterationcount = din.readint();
    
            if ((iterationcount < 0) || (iterationcount > 4 *  min_iterations))
            {
                throw new ioexception("key store corrupted.");
            }
    
            string cipheralg;
            if (version == 0)
            {
                cipheralg = "old" + store_cipher;
            }
            else
            {
                cipheralg = store_cipher;
            }

            cipher cipher = this.makepbecipher(cipheralg, cipher.decrypt_mode, password, salt, iterationcount);
            cipherinputstream cin = new cipherinputstream(din, cipher);

            digest dig = new sha1digest();
            digestinputstream  dgin = new digestinputstream(cin, dig);
    
            this.loadstore(dgin);

            // finalise our digest calculation
            byte[] hash = new byte[dig.getdigestsize()];
            dig.dofinal(hash, 0);

            // todo should this actually be reading the remainder of the stream?
            // read the original digest from the stream
            byte[] oldhash = new byte[dig.getdigestsize()];
            streams.readfully(cin, oldhash);

            if (!arrays.constanttimeareequal(hash, oldhash))
            {
                table.clear();
                throw new ioexception("keystore integrity check failed.");
            }
        }

        public void enginestore(outputstream stream, char[] password) 
            throws ioexception
        {
            cipher              cipher;
            dataoutputstream    dout = new dataoutputstream(stream);
            byte[]              salt = new byte[store_salt_size];
            int                 iterationcount = min_iterations + (random.nextint() & 0x3ff);
    
            random.nextbytes(salt);
    
            dout.writeint(version);
            dout.writeint(salt.length);
            dout.write(salt);
            dout.writeint(iterationcount);
    
            cipher = this.makepbecipher(store_cipher, cipher.encrypt_mode, password, salt, iterationcount);
    
            cipheroutputstream  cout = new cipheroutputstream(dout, cipher);
            digestoutputstream  dgout = new digestoutputstream(new sha1digest());
    
            this.savestore(new teeoutputstream(cout, dgout));
    
            byte[]  dig = dgout.getdigest();

            cout.write(dig);
    
            cout.close();
        }
    }

    public static class std
       extends bckeystorespi
    {
        public std()
        {
            super(store_version);
        }
    }

    public static class version1
        extends bckeystorespi
    {
        public version1()
        {
            super(1);
        }
    }
}
