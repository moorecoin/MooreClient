package org.ripple.bouncycastle.jcajce.provider.keystore.pkcs12;

import java.io.bufferedinputstream;
import java.io.bytearrayinputstream;
import java.io.bytearrayoutputstream;
import java.io.ioexception;
import java.io.inputstream;
import java.io.outputstream;
import java.security.key;
import java.security.keystore;
import java.security.keystore.loadstoreparameter;
import java.security.keystore.protectionparameter;
import java.security.keystoreexception;
import java.security.keystorespi;
import java.security.nosuchalgorithmexception;
import java.security.principal;
import java.security.privatekey;
import java.security.provider;
import java.security.publickey;
import java.security.securerandom;
import java.security.unrecoverablekeyexception;
import java.security.cert.certificate;
import java.security.cert.certificateencodingexception;
import java.security.cert.certificateexception;
import java.security.cert.certificatefactory;
import java.security.cert.x509certificate;
import java.util.date;
import java.util.enumeration;
import java.util.hashtable;
import java.util.vector;

import javax.crypto.cipher;
import javax.crypto.mac;
import javax.crypto.secretkey;
import javax.crypto.secretkeyfactory;
import javax.crypto.spec.ivparameterspec;
import javax.crypto.spec.pbekeyspec;
import javax.crypto.spec.pbeparameterspec;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1encoding;
import org.ripple.bouncycastle.asn1.asn1inputstream;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1set;
import org.ripple.bouncycastle.asn1.beroctetstring;
import org.ripple.bouncycastle.asn1.beroutputstream;
import org.ripple.bouncycastle.asn1.derbmpstring;
import org.ripple.bouncycastle.asn1.dernull;
import org.ripple.bouncycastle.asn1.deroctetstring;
import org.ripple.bouncycastle.asn1.deroutputstream;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.derset;
import org.ripple.bouncycastle.asn1.pkcs.authenticatedsafe;
import org.ripple.bouncycastle.asn1.pkcs.certbag;
import org.ripple.bouncycastle.asn1.pkcs.contentinfo;
import org.ripple.bouncycastle.asn1.pkcs.encrypteddata;
import org.ripple.bouncycastle.asn1.pkcs.macdata;
import org.ripple.bouncycastle.asn1.pkcs.pbes2parameters;
import org.ripple.bouncycastle.asn1.pkcs.pbkdf2params;
import org.ripple.bouncycastle.asn1.pkcs.pkcs12pbeparams;
import org.ripple.bouncycastle.asn1.pkcs.pkcsobjectidentifiers;
import org.ripple.bouncycastle.asn1.pkcs.pfx;
import org.ripple.bouncycastle.asn1.pkcs.safebag;
import org.ripple.bouncycastle.asn1.util.asn1dump;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;
import org.ripple.bouncycastle.asn1.x509.authoritykeyidentifier;
import org.ripple.bouncycastle.asn1.x509.digestinfo;
import org.ripple.bouncycastle.asn1.x509.extension;
import org.ripple.bouncycastle.asn1.x509.subjectkeyidentifier;
import org.ripple.bouncycastle.asn1.x509.subjectpublickeyinfo;
import org.ripple.bouncycastle.asn1.x509.x509objectidentifiers;
import org.ripple.bouncycastle.jcajce.provider.config.pkcs12storeparameter;
import org.ripple.bouncycastle.jcajce.provider.symmetric.util.bcpbekey;
import org.ripple.bouncycastle.jcajce.provider.util.secretkeyutil;
import org.ripple.bouncycastle.jce.interfaces.bckeystore;
import org.ripple.bouncycastle.jce.interfaces.pkcs12bagattributecarrier;
import org.ripple.bouncycastle.jce.provider.bouncycastleprovider;
import org.ripple.bouncycastle.jce.provider.jdkpkcs12storeparameter;
import org.ripple.bouncycastle.util.arrays;
import org.ripple.bouncycastle.util.strings;
import org.ripple.bouncycastle.util.encoders.hex;

public class pkcs12keystorespi
    extends keystorespi
    implements pkcsobjectidentifiers, x509objectidentifiers, bckeystore
{
    private static final int salt_size = 20;
    private static final int min_iterations = 1024;

    private static final provider bcprovider = new bouncycastleprovider();

    private ignorescasehashtable keys = new ignorescasehashtable();
    private hashtable localids = new hashtable();
    private ignorescasehashtable certs = new ignorescasehashtable();
    private hashtable chaincerts = new hashtable();
    private hashtable keycerts = new hashtable();

    //
    // generic object types
    //
    static final int null = 0;
    static final int certificate = 1;
    static final int key = 2;
    static final int secret = 3;
    static final int sealed = 4;

    //
    // key types
    //
    static final int key_private = 0;
    static final int key_public = 1;
    static final int key_secret = 2;

    protected securerandom random = new securerandom();

    // use of final causes problems with jdk 1.2 compiler
    private certificatefactory certfact;
    private asn1objectidentifier keyalgorithm;
    private asn1objectidentifier certalgorithm;

    private class certid
    {
        byte[] id;

        certid(
            publickey key)
        {
            this.id = createsubjectkeyid(key).getkeyidentifier();
        }

        certid(
            byte[] id)
        {
            this.id = id;
        }

        public int hashcode()
        {
            return arrays.hashcode(id);
        }

        public boolean equals(
            object o)
        {
            if (o == this)
            {
                return true;
            }

            if (!(o instanceof certid))
            {
                return false;
            }

            certid cid = (certid)o;

            return arrays.areequal(id, cid.id);
        }
    }

    public pkcs12keystorespi(
        provider provider,
        asn1objectidentifier keyalgorithm,
        asn1objectidentifier certalgorithm)
    {
        this.keyalgorithm = keyalgorithm;
        this.certalgorithm = certalgorithm;

        try
        {
            if (provider != null)
            {
                certfact = certificatefactory.getinstance("x.509", provider);
            }
            else
            {
                certfact = certificatefactory.getinstance("x.509");
            }
        }
        catch (exception e)
        {
            throw new illegalargumentexception("can't create cert factory - " + e.tostring());
        }
    }

    private subjectkeyidentifier createsubjectkeyid(
        publickey pubkey)
    {
        try
        {
            subjectpublickeyinfo info = new subjectpublickeyinfo(
                (asn1sequence)asn1primitive.frombytearray(pubkey.getencoded()));

            return new subjectkeyidentifier(info);
        }
        catch (exception e)
        {
            throw new runtimeexception("error creating key");
        }
    }

    public void setrandom(
        securerandom rand)
    {
        this.random = rand;
    }

    public enumeration enginealiases()
    {
        hashtable tab = new hashtable();

        enumeration e = certs.keys();
        while (e.hasmoreelements())
        {
            tab.put(e.nextelement(), "cert");
        }

        e = keys.keys();
        while (e.hasmoreelements())
        {
            string a = (string)e.nextelement();
            if (tab.get(a) == null)
            {
                tab.put(a, "key");
            }
        }

        return tab.keys();
    }

    public boolean enginecontainsalias(
        string alias)
    {
        return (certs.get(alias) != null || keys.get(alias) != null);
    }

    /**
     * this is not quite complete - we should follow up on the chain, a bit
     * tricky if a certificate appears in more than one chain...
     */
    public void enginedeleteentry(
        string alias)
        throws keystoreexception
    {
        key k = (key)keys.remove(alias);

        certificate c = (certificate)certs.remove(alias);

        if (c != null)
        {
            chaincerts.remove(new certid(c.getpublickey()));
        }

        if (k != null)
        {
            string id = (string)localids.remove(alias);
            if (id != null)
            {
                c = (certificate)keycerts.remove(id);
            }
            if (c != null)
            {
                chaincerts.remove(new certid(c.getpublickey()));
            }
        }
    }

    /**
     * simply return the cert for the private key
     */
    public certificate enginegetcertificate(
        string alias)
    {
        if (alias == null)
        {
            throw new illegalargumentexception("null alias passed to getcertificate.");
        }

        certificate c = (certificate)certs.get(alias);

        //
        // look up the key table - and try the local key id
        //
        if (c == null)
        {
            string id = (string)localids.get(alias);
            if (id != null)
            {
                c = (certificate)keycerts.get(id);
            }
            else
            {
                c = (certificate)keycerts.get(alias);
            }
        }

        return c;
    }

    public string enginegetcertificatealias(
        certificate cert)
    {
        enumeration c = certs.elements();
        enumeration k = certs.keys();

        while (c.hasmoreelements())
        {
            certificate tc = (certificate)c.nextelement();
            string ta = (string)k.nextelement();

            if (tc.equals(cert))
            {
                return ta;
            }
        }

        c = keycerts.elements();
        k = keycerts.keys();

        while (c.hasmoreelements())
        {
            certificate tc = (certificate)c.nextelement();
            string ta = (string)k.nextelement();

            if (tc.equals(cert))
            {
                return ta;
            }
        }

        return null;
    }

    public certificate[] enginegetcertificatechain(
        string alias)
    {
        if (alias == null)
        {
            throw new illegalargumentexception("null alias passed to getcertificatechain.");
        }

        if (!engineiskeyentry(alias))
        {
            return null;
        }

        certificate c = enginegetcertificate(alias);

        if (c != null)
        {
            vector cs = new vector();

            while (c != null)
            {
                x509certificate x509c = (x509certificate)c;
                certificate nextc = null;

                byte[] bytes = x509c.getextensionvalue(extension.authoritykeyidentifier.getid());
                if (bytes != null)
                {
                    try
                    {
                        asn1inputstream ain = new asn1inputstream(bytes);

                        byte[] authbytes = ((asn1octetstring)ain.readobject()).getoctets();
                        ain = new asn1inputstream(authbytes);

                        authoritykeyidentifier id = authoritykeyidentifier.getinstance(ain.readobject());
                        if (id.getkeyidentifier() != null)
                        {
                            nextc = (certificate)chaincerts.get(new certid(id.getkeyidentifier()));
                        }

                    }
                    catch (ioexception e)
                    {
                        throw new runtimeexception(e.tostring());
                    }
                }

                if (nextc == null)
                {
                    //
                    // no authority key id, try the issuer dn
                    //
                    principal i = x509c.getissuerdn();
                    principal s = x509c.getsubjectdn();

                    if (!i.equals(s))
                    {
                        enumeration e = chaincerts.keys();

                        while (e.hasmoreelements())
                        {
                            x509certificate crt = (x509certificate)chaincerts.get(e.nextelement());
                            principal sub = crt.getsubjectdn();
                            if (sub.equals(i))
                            {
                                try
                                {
                                    x509c.verify(crt.getpublickey());
                                    nextc = crt;
                                    break;
                                }
                                catch (exception ex)
                                {
                                    // continue
                                }
                            }
                        }
                    }
                }

                cs.addelement(c);
                if (nextc != c)     // self signed - end of the chain
                {
                    c = nextc;
                }
                else
                {
                    c = null;
                }
            }

            certificate[] certchain = new certificate[cs.size()];

            for (int i = 0; i != certchain.length; i++)
            {
                certchain[i] = (certificate)cs.elementat(i);
            }

            return certchain;
        }

        return null;
    }

    public date enginegetcreationdate(string alias)
    {
        if (alias == null)
        {
            throw new nullpointerexception("alias == null");
        }
        if (keys.get(alias) == null && certs.get(alias) == null)
        {
            return null;
        }
        return new date();
    }

    public key enginegetkey(
        string alias,
        char[] password)
        throws nosuchalgorithmexception, unrecoverablekeyexception
    {
        if (alias == null)
        {
            throw new illegalargumentexception("null alias passed to getkey.");
        }

        return (key)keys.get(alias);
    }

    public boolean engineiscertificateentry(
        string alias)
    {
        return (certs.get(alias) != null && keys.get(alias) == null);
    }

    public boolean engineiskeyentry(
        string alias)
    {
        return (keys.get(alias) != null);
    }

    public void enginesetcertificateentry(
        string alias,
        certificate cert)
        throws keystoreexception
    {
        if (keys.get(alias) != null)
        {
            throw new keystoreexception("there is a key entry with the name " + alias + ".");
        }

        certs.put(alias, cert);
        chaincerts.put(new certid(cert.getpublickey()), cert);
    }

    public void enginesetkeyentry(
        string alias,
        byte[] key,
        certificate[] chain)
        throws keystoreexception
    {
        throw new runtimeexception("operation not supported");
    }

    public void enginesetkeyentry(
        string alias,
        key key,
        char[] password,
        certificate[] chain)
        throws keystoreexception
    {
        if (!(key instanceof privatekey))
        {
            throw new keystoreexception("pkcs12 does not support non-privatekeys");
        }

        if ((key instanceof privatekey) && (chain == null))
        {
            throw new keystoreexception("no certificate chain for private key");
        }

        if (keys.get(alias) != null)
        {
            enginedeleteentry(alias);
        }

        keys.put(alias, key);
        if (chain != null)
        {
            certs.put(alias, chain[0]);

            for (int i = 0; i != chain.length; i++)
            {
                chaincerts.put(new certid(chain[i].getpublickey()), chain[i]);
            }
        }
    }

    public int enginesize()
    {
        hashtable tab = new hashtable();

        enumeration e = certs.keys();
        while (e.hasmoreelements())
        {
            tab.put(e.nextelement(), "cert");
        }

        e = keys.keys();
        while (e.hasmoreelements())
        {
            string a = (string)e.nextelement();
            if (tab.get(a) == null)
            {
                tab.put(a, "key");
            }
        }

        return tab.size();
    }

    protected privatekey unwrapkey(
        algorithmidentifier algid,
        byte[] data,
        char[] password,
        boolean wrongpkcs12zero)
        throws ioexception
    {
        asn1objectidentifier algorithm = algid.getalgorithm();
        try
        {
            if (algorithm.on(pkcsobjectidentifiers.pkcs_12pbeids))
            {
                pkcs12pbeparams pbeparams = pkcs12pbeparams.getinstance(algid.getparameters());

                pbekeyspec pbespec = new pbekeyspec(password);
                privatekey out;

                secretkeyfactory keyfact = secretkeyfactory.getinstance(
                    algorithm.getid(), bcprovider);
                pbeparameterspec defparams = new pbeparameterspec(
                    pbeparams.getiv(),
                    pbeparams.getiterations().intvalue());

                secretkey k = keyfact.generatesecret(pbespec);

                ((bcpbekey)k).settrywrongpkcs12zero(wrongpkcs12zero);

                cipher cipher = cipher.getinstance(algorithm.getid(), bcprovider);

                cipher.init(cipher.unwrap_mode, k, defparams);

                // we pass "" as the key algorithm type as it is unknown at this point
                return (privatekey)cipher.unwrap(data, "", cipher.private_key);
            }
            else if (algorithm.equals(pkcsobjectidentifiers.id_pbes2))
            {
                pbes2parameters alg = pbes2parameters.getinstance(algid.getparameters());
                pbkdf2params func = pbkdf2params.getinstance(alg.getkeyderivationfunc().getparameters());

                secretkeyfactory keyfact = secretkeyfactory.getinstance(alg.getkeyderivationfunc().getalgorithm().getid(), bcprovider);

                secretkey k = keyfact.generatesecret(new pbekeyspec(password, func.getsalt(), func.getiterationcount().intvalue(), secretkeyutil.getkeysize(alg.getencryptionscheme().getalgorithm())));

                cipher cipher = cipher.getinstance(alg.getencryptionscheme().getalgorithm().getid(), bcprovider);

                cipher.init(cipher.unwrap_mode, k, new ivparameterspec(asn1octetstring.getinstance(alg.getencryptionscheme().getparameters()).getoctets()));

                // we pass "" as the key algorithm type as it is unknown at this point
                return (privatekey)cipher.unwrap(data, "", cipher.private_key);
            }
        }
        catch (exception e)
        {
            throw new ioexception("exception unwrapping private key - " + e.tostring());
        }

        throw new ioexception("exception unwrapping private key - cannot recognise: " + algorithm);
    }

    protected byte[] wrapkey(
        string algorithm,
        key key,
        pkcs12pbeparams pbeparams,
        char[] password)
        throws ioexception
    {
        pbekeyspec pbespec = new pbekeyspec(password);
        byte[] out;

        try
        {
            secretkeyfactory keyfact = secretkeyfactory.getinstance(
                algorithm, bcprovider);
            pbeparameterspec defparams = new pbeparameterspec(
                pbeparams.getiv(),
                pbeparams.getiterations().intvalue());

            cipher cipher = cipher.getinstance(algorithm, bcprovider);

            cipher.init(cipher.wrap_mode, keyfact.generatesecret(pbespec), defparams);

            out = cipher.wrap(key);
        }
        catch (exception e)
        {
            throw new ioexception("exception encrypting data - " + e.tostring());
        }

        return out;
    }

    protected byte[] cryptdata(
        boolean forencryption,
        algorithmidentifier algid,
        char[] password,
        boolean wrongpkcs12zero,
        byte[] data)
        throws ioexception
    {
        string algorithm = algid.getalgorithm().getid();
        pkcs12pbeparams pbeparams = pkcs12pbeparams.getinstance(algid.getparameters());
        pbekeyspec pbespec = new pbekeyspec(password);

        try
        {
            secretkeyfactory keyfact = secretkeyfactory.getinstance(algorithm, bcprovider);
            pbeparameterspec defparams = new pbeparameterspec(
                pbeparams.getiv(),
                pbeparams.getiterations().intvalue());
            bcpbekey key = (bcpbekey)keyfact.generatesecret(pbespec);

            key.settrywrongpkcs12zero(wrongpkcs12zero);

            cipher cipher = cipher.getinstance(algorithm, bcprovider);
            int mode = forencryption ? cipher.encrypt_mode : cipher.decrypt_mode;
            cipher.init(mode, key, defparams);
            return cipher.dofinal(data);
        }
        catch (exception e)
        {
            throw new ioexception("exception decrypting data - " + e.tostring());
        }
    }

    public void engineload(
        inputstream stream,
        char[] password)
        throws ioexception
    {
        if (stream == null)     // just initialising
        {
            return;
        }

        if (password == null)
        {
            throw new nullpointerexception("no password supplied for pkcs#12 keystore.");
        }

        bufferedinputstream bufin = new bufferedinputstream(stream);

        bufin.mark(10);

        int head = bufin.read();

        if (head != 0x30)
        {
            throw new ioexception("stream does not represent a pkcs12 key store");
        }

        bufin.reset();

        asn1inputstream bin = new asn1inputstream(bufin);
        asn1sequence obj = (asn1sequence)bin.readobject();
        pfx bag = pfx.getinstance(obj);
        contentinfo info = bag.getauthsafe();
        vector chain = new vector();
        boolean unmarkedkey = false;
        boolean wrongpkcs12zero = false;

        if (bag.getmacdata() != null)           // check the mac code
        {
            macdata mdata = bag.getmacdata();
            digestinfo dinfo = mdata.getmac();
            algorithmidentifier algid = dinfo.getalgorithmid();
            byte[] salt = mdata.getsalt();
            int itcount = mdata.getiterationcount().intvalue();

            byte[] data = ((asn1octetstring)info.getcontent()).getoctets();

            try
            {
                byte[] res = calculatepbemac(algid.getalgorithm(), salt, itcount, password, false, data);
                byte[] dig = dinfo.getdigest();

                if (!arrays.constanttimeareequal(res, dig))
                {
                    if (password.length > 0)
                    {
                        throw new ioexception("pkcs12 key store mac invalid - wrong password or corrupted file.");
                    }

                    // try with incorrect zero length password
                    res = calculatepbemac(algid.getalgorithm(), salt, itcount, password, true, data);

                    if (!arrays.constanttimeareequal(res, dig))
                    {
                        throw new ioexception("pkcs12 key store mac invalid - wrong password or corrupted file.");
                    }

                    wrongpkcs12zero = true;
                }
            }
            catch (ioexception e)
            {
                throw e;
            }
            catch (exception e)
            {
                throw new ioexception("error constructing mac: " + e.tostring());
            }
        }

        keys = new ignorescasehashtable();
        localids = new hashtable();

        if (info.getcontenttype().equals(data))
        {
            bin = new asn1inputstream(((asn1octetstring)info.getcontent()).getoctets());

            authenticatedsafe authsafe = authenticatedsafe.getinstance(bin.readobject());
            contentinfo[] c = authsafe.getcontentinfo();

            for (int i = 0; i != c.length; i++)
            {
                if (c[i].getcontenttype().equals(data))
                {
                    asn1inputstream din = new asn1inputstream(((asn1octetstring)c[i].getcontent()).getoctets());
                    asn1sequence seq = (asn1sequence)din.readobject();

                    for (int j = 0; j != seq.size(); j++)
                    {
                        safebag b = safebag.getinstance(seq.getobjectat(j));
                        if (b.getbagid().equals(pkcs8shroudedkeybag))
                        {
                            org.ripple.bouncycastle.asn1.pkcs.encryptedprivatekeyinfo ein = org.ripple.bouncycastle.asn1.pkcs.encryptedprivatekeyinfo.getinstance(b.getbagvalue());
                            privatekey privkey = unwrapkey(ein.getencryptionalgorithm(), ein.getencrypteddata(), password, wrongpkcs12zero);

                            //
                            // set the attributes on the key
                            //
                            pkcs12bagattributecarrier bagattr = (pkcs12bagattributecarrier)privkey;
                            string alias = null;
                            asn1octetstring localid = null;

                            if (b.getbagattributes() != null)
                            {
                                enumeration e = b.getbagattributes().getobjects();
                                while (e.hasmoreelements())
                                {
                                    asn1sequence sq = (asn1sequence)e.nextelement();
                                    asn1objectidentifier aoid = (asn1objectidentifier)sq.getobjectat(0);
                                    asn1set attrset = (asn1set)sq.getobjectat(1);
                                    asn1primitive attr = null;

                                    if (attrset.size() > 0)
                                    {
                                        attr = (asn1primitive)attrset.getobjectat(0);

                                        asn1encodable existing = bagattr.getbagattribute(aoid);
                                        if (existing != null)
                                        {
                                            // ok, but the value has to be the same
                                            if (!existing.toasn1primitive().equals(attr))
                                            {
                                                throw new ioexception(
                                                    "attempt to add existing attribute with different value");
                                            }
                                        }
                                        else
                                        {
                                            bagattr.setbagattribute(aoid, attr);
                                        }
                                    }

                                    if (aoid.equals(pkcs_9_at_friendlyname))
                                    {
                                        alias = ((derbmpstring)attr).getstring();
                                        keys.put(alias, privkey);
                                    }
                                    else if (aoid.equals(pkcs_9_at_localkeyid))
                                    {
                                        localid = (asn1octetstring)attr;
                                    }
                                }
                            }

                            if (localid != null)
                            {
                                string name = new string(hex.encode(localid.getoctets()));

                                if (alias == null)
                                {
                                    keys.put(name, privkey);
                                }
                                else
                                {
                                    localids.put(alias, name);
                                }
                            }
                            else
                            {
                                unmarkedkey = true;
                                keys.put("unmarked", privkey);
                            }
                        }
                        else if (b.getbagid().equals(certbag))
                        {
                            chain.addelement(b);
                        }
                        else
                        {
                            system.out.println("extra in data " + b.getbagid());
                            system.out.println(asn1dump.dumpasstring(b));
                        }
                    }
                }
                else if (c[i].getcontenttype().equals(encrypteddata))
                {
                    encrypteddata d = encrypteddata.getinstance(c[i].getcontent());
                    byte[] octets = cryptdata(false, d.getencryptionalgorithm(),
                        password, wrongpkcs12zero, d.getcontent().getoctets());
                    asn1sequence seq = (asn1sequence)asn1primitive.frombytearray(octets);

                    for (int j = 0; j != seq.size(); j++)
                    {
                        safebag b = safebag.getinstance(seq.getobjectat(j));

                        if (b.getbagid().equals(certbag))
                        {
                            chain.addelement(b);
                        }
                        else if (b.getbagid().equals(pkcs8shroudedkeybag))
                        {
                            org.ripple.bouncycastle.asn1.pkcs.encryptedprivatekeyinfo ein = org.ripple.bouncycastle.asn1.pkcs.encryptedprivatekeyinfo.getinstance(b.getbagvalue());
                            privatekey privkey = unwrapkey(ein.getencryptionalgorithm(), ein.getencrypteddata(), password, wrongpkcs12zero);

                            //
                            // set the attributes on the key
                            //
                            pkcs12bagattributecarrier bagattr = (pkcs12bagattributecarrier)privkey;
                            string alias = null;
                            asn1octetstring localid = null;

                            enumeration e = b.getbagattributes().getobjects();
                            while (e.hasmoreelements())
                            {
                                asn1sequence sq = (asn1sequence)e.nextelement();
                                asn1objectidentifier aoid = (asn1objectidentifier)sq.getobjectat(0);
                                asn1set attrset = (asn1set)sq.getobjectat(1);
                                asn1primitive attr = null;

                                if (attrset.size() > 0)
                                {
                                    attr = (asn1primitive)attrset.getobjectat(0);

                                    asn1encodable existing = bagattr.getbagattribute(aoid);
                                    if (existing != null)
                                    {
                                        // ok, but the value has to be the same
                                        if (!existing.toasn1primitive().equals(attr))
                                        {
                                            throw new ioexception(
                                                "attempt to add existing attribute with different value");
                                        }
                                    }
                                    else
                                    {
                                        bagattr.setbagattribute(aoid, attr);
                                    }
                                }

                                if (aoid.equals(pkcs_9_at_friendlyname))
                                {
                                    alias = ((derbmpstring)attr).getstring();
                                    keys.put(alias, privkey);
                                }
                                else if (aoid.equals(pkcs_9_at_localkeyid))
                                {
                                    localid = (asn1octetstring)attr;
                                }
                            }

                            string name = new string(hex.encode(localid.getoctets()));

                            if (alias == null)
                            {
                                keys.put(name, privkey);
                            }
                            else
                            {
                                localids.put(alias, name);
                            }
                        }
                        else if (b.getbagid().equals(keybag))
                        {
                            org.ripple.bouncycastle.asn1.pkcs.privatekeyinfo kinfo = org.ripple.bouncycastle.asn1.pkcs.privatekeyinfo.getinstance(b.getbagvalue());
                            privatekey privkey = bouncycastleprovider.getprivatekey(kinfo);

                            //
                            // set the attributes on the key
                            //
                            pkcs12bagattributecarrier bagattr = (pkcs12bagattributecarrier)privkey;
                            string alias = null;
                            asn1octetstring localid = null;

                            enumeration e = b.getbagattributes().getobjects();
                            while (e.hasmoreelements())
                            {
                                asn1sequence sq = (asn1sequence)e.nextelement();
                                asn1objectidentifier aoid = (asn1objectidentifier)sq.getobjectat(0);
                                asn1set attrset = (asn1set)sq.getobjectat(1);
                                asn1primitive attr = null;

                                if (attrset.size() > 0)
                                {
                                    attr = (asn1primitive)attrset.getobjectat(0);

                                    asn1encodable existing = bagattr.getbagattribute(aoid);
                                    if (existing != null)
                                    {
                                        // ok, but the value has to be the same
                                        if (!existing.toasn1primitive().equals(attr))
                                        {
                                            throw new ioexception(
                                                "attempt to add existing attribute with different value");
                                        }
                                    }
                                    else
                                    {
                                        bagattr.setbagattribute(aoid, attr);
                                    }
                                }

                                if (aoid.equals(pkcs_9_at_friendlyname))
                                {
                                    alias = ((derbmpstring)attr).getstring();
                                    keys.put(alias, privkey);
                                }
                                else if (aoid.equals(pkcs_9_at_localkeyid))
                                {
                                    localid = (asn1octetstring)attr;
                                }
                            }

                            string name = new string(hex.encode(localid.getoctets()));

                            if (alias == null)
                            {
                                keys.put(name, privkey);
                            }
                            else
                            {
                                localids.put(alias, name);
                            }
                        }
                        else
                        {
                            system.out.println("extra in encrypteddata " + b.getbagid());
                            system.out.println(asn1dump.dumpasstring(b));
                        }
                    }
                }
                else
                {
                    system.out.println("extra " + c[i].getcontenttype().getid());
                    system.out.println("extra " + asn1dump.dumpasstring(c[i].getcontent()));
                }
            }
        }

        certs = new ignorescasehashtable();
        chaincerts = new hashtable();
        keycerts = new hashtable();

        for (int i = 0; i != chain.size(); i++)
        {
            safebag b = (safebag)chain.elementat(i);
            certbag cb = certbag.getinstance(b.getbagvalue());

            if (!cb.getcertid().equals(x509certificate))
            {
                throw new runtimeexception("unsupported certificate type: " + cb.getcertid());
            }

            certificate cert;

            try
            {
                bytearrayinputstream cin = new bytearrayinputstream(
                    ((asn1octetstring)cb.getcertvalue()).getoctets());
                cert = certfact.generatecertificate(cin);
            }
            catch (exception e)
            {
                throw new runtimeexception(e.tostring());
            }

            //
            // set the attributes
            //
            asn1octetstring localid = null;
            string alias = null;

            if (b.getbagattributes() != null)
            {
                enumeration e = b.getbagattributes().getobjects();
                while (e.hasmoreelements())
                {
                    asn1sequence sq = (asn1sequence)e.nextelement();
                    asn1objectidentifier oid = (asn1objectidentifier)sq.getobjectat(0);
                    asn1primitive attr = (asn1primitive)((asn1set)sq.getobjectat(1)).getobjectat(0);
                    pkcs12bagattributecarrier bagattr = null;

                    if (cert instanceof pkcs12bagattributecarrier)
                    {
                        bagattr = (pkcs12bagattributecarrier)cert;

                        asn1encodable existing = bagattr.getbagattribute(oid);
                        if (existing != null)
                        {
                            // ok, but the value has to be the same
                            if (!existing.toasn1primitive().equals(attr))
                            {
                                throw new ioexception(
                                    "attempt to add existing attribute with different value");
                            }
                        }
                        else
                        {
                            bagattr.setbagattribute(oid, attr);
                        }
                    }

                    if (oid.equals(pkcs_9_at_friendlyname))
                    {
                        alias = ((derbmpstring)attr).getstring();
                    }
                    else if (oid.equals(pkcs_9_at_localkeyid))
                    {
                        localid = (asn1octetstring)attr;
                    }
                }
            }

            chaincerts.put(new certid(cert.getpublickey()), cert);

            if (unmarkedkey)
            {
                if (keycerts.isempty())
                {
                    string name = new string(hex.encode(createsubjectkeyid(cert.getpublickey()).getkeyidentifier()));

                    keycerts.put(name, cert);
                    keys.put(name, keys.remove("unmarked"));
                }
            }
            else
            {
                //
                // the local key id needs to override the friendly name
                //
                if (localid != null)
                {
                    string name = new string(hex.encode(localid.getoctets()));

                    keycerts.put(name, cert);
                }
                if (alias != null)
                {
                    certs.put(alias, cert);
                }
            }
        }
    }

    public void enginestore(loadstoreparameter param)
        throws ioexception,
        nosuchalgorithmexception, certificateexception
    {
        if (param == null)
        {
            throw new illegalargumentexception("'param' arg cannot be null");
        }

        if (!(param instanceof pkcs12storeparameter || param instanceof jdkpkcs12storeparameter))
        {
            throw new illegalargumentexception(
                "no support for 'param' of type " + param.getclass().getname());
        }

        pkcs12storeparameter bcparam;

        if (param instanceof pkcs12storeparameter)
        {
            bcparam = (pkcs12storeparameter)param;
        }
        else
        {
            bcparam = new pkcs12storeparameter(((jdkpkcs12storeparameter)param).getoutputstream(),
                param.getprotectionparameter(), ((jdkpkcs12storeparameter)param).isusederencoding());
        }

        char[] password;
        protectionparameter protparam = param.getprotectionparameter();
        if (protparam == null)
        {
            password = null;
        }
        else if (protparam instanceof keystore.passwordprotection)
        {
            password = ((keystore.passwordprotection)protparam).getpassword();
        }
        else
        {
            throw new illegalargumentexception(
                "no support for protection parameter of type " + protparam.getclass().getname());
        }

        dostore(bcparam.getoutputstream(), password, bcparam.isforderencoding());
    }

    public void enginestore(outputstream stream, char[] password)
        throws ioexception
    {
        dostore(stream, password, false);
    }

    private void dostore(outputstream stream, char[] password, boolean usederencoding)
        throws ioexception
    {
        if (password == null)
        {
            throw new nullpointerexception("no password supplied for pkcs#12 keystore.");
        }

        //
        // handle the key
        //
        asn1encodablevector keys = new asn1encodablevector();


        enumeration ks = keys.keys();

        while (ks.hasmoreelements())
        {
            byte[] ksalt = new byte[salt_size];

            random.nextbytes(ksalt);

            string name = (string)ks.nextelement();
            privatekey privkey = (privatekey)keys.get(name);
            pkcs12pbeparams kparams = new pkcs12pbeparams(ksalt, min_iterations);
            byte[] kbytes = wrapkey(keyalgorithm.getid(), privkey, kparams, password);
            algorithmidentifier kalgid = new algorithmidentifier(keyalgorithm, kparams.toasn1primitive());
            org.ripple.bouncycastle.asn1.pkcs.encryptedprivatekeyinfo kinfo = new org.ripple.bouncycastle.asn1.pkcs.encryptedprivatekeyinfo(kalgid, kbytes);
            boolean attrset = false;
            asn1encodablevector kname = new asn1encodablevector();

            if (privkey instanceof pkcs12bagattributecarrier)
            {
                pkcs12bagattributecarrier bagattrs = (pkcs12bagattributecarrier)privkey;
                //
                // make sure we are using the local alias on store
                //
                derbmpstring nm = (derbmpstring)bagattrs.getbagattribute(pkcs_9_at_friendlyname);
                if (nm == null || !nm.getstring().equals(name))
                {
                    bagattrs.setbagattribute(pkcs_9_at_friendlyname, new derbmpstring(name));
                }

                //
                // make sure we have a local key-id
                //
                if (bagattrs.getbagattribute(pkcs_9_at_localkeyid) == null)
                {
                    certificate ct = enginegetcertificate(name);

                    bagattrs.setbagattribute(pkcs_9_at_localkeyid, createsubjectkeyid(ct.getpublickey()));
                }

                enumeration e = bagattrs.getbagattributekeys();

                while (e.hasmoreelements())
                {
                    asn1objectidentifier oid = (asn1objectidentifier)e.nextelement();
                    asn1encodablevector kseq = new asn1encodablevector();

                    kseq.add(oid);
                    kseq.add(new derset(bagattrs.getbagattribute(oid)));

                    attrset = true;

                    kname.add(new dersequence(kseq));
                }
            }

            if (!attrset)
            {
                //
                // set a default friendly name (from the key id) and local id
                //
                asn1encodablevector kseq = new asn1encodablevector();
                certificate ct = enginegetcertificate(name);

                kseq.add(pkcs_9_at_localkeyid);
                kseq.add(new derset(createsubjectkeyid(ct.getpublickey())));

                kname.add(new dersequence(kseq));

                kseq = new asn1encodablevector();

                kseq.add(pkcs_9_at_friendlyname);
                kseq.add(new derset(new derbmpstring(name)));

                kname.add(new dersequence(kseq));
            }

            safebag kbag = new safebag(pkcs8shroudedkeybag, kinfo.toasn1primitive(), new derset(kname));
            keys.add(kbag);
        }

        byte[] keysencoded = new dersequence(keys).getencoded(asn1encoding.der);
        beroctetstring keystring = new beroctetstring(keysencoded);

        //
        // certificate processing
        //
        byte[] csalt = new byte[salt_size];

        random.nextbytes(csalt);

        asn1encodablevector certseq = new asn1encodablevector();
        pkcs12pbeparams cparams = new pkcs12pbeparams(csalt, min_iterations);
        algorithmidentifier calgid = new algorithmidentifier(certalgorithm, cparams.toasn1primitive());
        hashtable donecerts = new hashtable();

        enumeration cs = keys.keys();
        while (cs.hasmoreelements())
        {
            try
            {
                string name = (string)cs.nextelement();
                certificate cert = enginegetcertificate(name);
                boolean cattrset = false;
                certbag cbag = new certbag(
                    x509certificate,
                    new deroctetstring(cert.getencoded()));
                asn1encodablevector fname = new asn1encodablevector();

                if (cert instanceof pkcs12bagattributecarrier)
                {
                    pkcs12bagattributecarrier bagattrs = (pkcs12bagattributecarrier)cert;
                    //
                    // make sure we are using the local alias on store
                    //
                    derbmpstring nm = (derbmpstring)bagattrs.getbagattribute(pkcs_9_at_friendlyname);
                    if (nm == null || !nm.getstring().equals(name))
                    {
                        bagattrs.setbagattribute(pkcs_9_at_friendlyname, new derbmpstring(name));
                    }

                    //
                    // make sure we have a local key-id
                    //
                    if (bagattrs.getbagattribute(pkcs_9_at_localkeyid) == null)
                    {
                        bagattrs.setbagattribute(pkcs_9_at_localkeyid, createsubjectkeyid(cert.getpublickey()));
                    }

                    enumeration e = bagattrs.getbagattributekeys();

                    while (e.hasmoreelements())
                    {
                        asn1objectidentifier oid = (asn1objectidentifier)e.nextelement();
                        asn1encodablevector fseq = new asn1encodablevector();

                        fseq.add(oid);
                        fseq.add(new derset(bagattrs.getbagattribute(oid)));
                        fname.add(new dersequence(fseq));

                        cattrset = true;
                    }
                }

                if (!cattrset)
                {
                    asn1encodablevector fseq = new asn1encodablevector();

                    fseq.add(pkcs_9_at_localkeyid);
                    fseq.add(new derset(createsubjectkeyid(cert.getpublickey())));
                    fname.add(new dersequence(fseq));

                    fseq = new asn1encodablevector();

                    fseq.add(pkcs_9_at_friendlyname);
                    fseq.add(new derset(new derbmpstring(name)));

                    fname.add(new dersequence(fseq));
                }

                safebag sbag = new safebag(certbag, cbag.toasn1primitive(), new derset(fname));

                certseq.add(sbag);

                donecerts.put(cert, cert);
            }
            catch (certificateencodingexception e)
            {
                throw new ioexception("error encoding certificate: " + e.tostring());
            }
        }

        cs = certs.keys();
        while (cs.hasmoreelements())
        {
            try
            {
                string certid = (string)cs.nextelement();
                certificate cert = (certificate)certs.get(certid);
                boolean cattrset = false;

                if (keys.get(certid) != null)
                {
                    continue;
                }

                certbag cbag = new certbag(
                    x509certificate,
                    new deroctetstring(cert.getencoded()));
                asn1encodablevector fname = new asn1encodablevector();

                if (cert instanceof pkcs12bagattributecarrier)
                {
                    pkcs12bagattributecarrier bagattrs = (pkcs12bagattributecarrier)cert;
                    //
                    // make sure we are using the local alias on store
                    //
                    derbmpstring nm = (derbmpstring)bagattrs.getbagattribute(pkcs_9_at_friendlyname);
                    if (nm == null || !nm.getstring().equals(certid))
                    {
                        bagattrs.setbagattribute(pkcs_9_at_friendlyname, new derbmpstring(certid));
                    }

                    enumeration e = bagattrs.getbagattributekeys();

                    while (e.hasmoreelements())
                    {
                        asn1objectidentifier oid = (asn1objectidentifier)e.nextelement();

                        // a certificate not immediately linked to a key doesn't require
                        // a localkeyid and will confuse some pkcs12 implementations.
                        //
                        // if we find one, we'll prune it out.
                        if (oid.equals(pkcsobjectidentifiers.pkcs_9_at_localkeyid))
                        {
                            continue;
                        }

                        asn1encodablevector fseq = new asn1encodablevector();

                        fseq.add(oid);
                        fseq.add(new derset(bagattrs.getbagattribute(oid)));
                        fname.add(new dersequence(fseq));

                        cattrset = true;
                    }
                }

                if (!cattrset)
                {
                    asn1encodablevector fseq = new asn1encodablevector();

                    fseq.add(pkcs_9_at_friendlyname);
                    fseq.add(new derset(new derbmpstring(certid)));

                    fname.add(new dersequence(fseq));
                }

                safebag sbag = new safebag(certbag, cbag.toasn1primitive(), new derset(fname));

                certseq.add(sbag);

                donecerts.put(cert, cert);
            }
            catch (certificateencodingexception e)
            {
                throw new ioexception("error encoding certificate: " + e.tostring());
            }
        }

        cs = chaincerts.keys();
        while (cs.hasmoreelements())
        {
            try
            {
                certid certid = (certid)cs.nextelement();
                certificate cert = (certificate)chaincerts.get(certid);

                if (donecerts.get(cert) != null)
                {
                    continue;
                }

                certbag cbag = new certbag(
                    x509certificate,
                    new deroctetstring(cert.getencoded()));
                asn1encodablevector fname = new asn1encodablevector();

                if (cert instanceof pkcs12bagattributecarrier)
                {
                    pkcs12bagattributecarrier bagattrs = (pkcs12bagattributecarrier)cert;
                    enumeration e = bagattrs.getbagattributekeys();

                    while (e.hasmoreelements())
                    {
                        asn1objectidentifier oid = (asn1objectidentifier)e.nextelement();

                        // a certificate not immediately linked to a key doesn't require
                        // a localkeyid and will confuse some pkcs12 implementations.
                        //
                        // if we find one, we'll prune it out.
                        if (oid.equals(pkcsobjectidentifiers.pkcs_9_at_localkeyid))
                        {
                            continue;
                        }

                        asn1encodablevector fseq = new asn1encodablevector();

                        fseq.add(oid);
                        fseq.add(new derset(bagattrs.getbagattribute(oid)));
                        fname.add(new dersequence(fseq));
                    }
                }

                safebag sbag = new safebag(certbag, cbag.toasn1primitive(), new derset(fname));

                certseq.add(sbag);
            }
            catch (certificateencodingexception e)
            {
                throw new ioexception("error encoding certificate: " + e.tostring());
            }
        }

        byte[] certseqencoded = new dersequence(certseq).getencoded(asn1encoding.der);
        byte[] certbytes = cryptdata(true, calgid, password, false, certseqencoded);
        encrypteddata cinfo = new encrypteddata(data, calgid, new beroctetstring(certbytes));

        contentinfo[] info = new contentinfo[]
            {
                new contentinfo(data, keystring),
                new contentinfo(encrypteddata, cinfo.toasn1primitive())
            };

        authenticatedsafe auth = new authenticatedsafe(info);

        bytearrayoutputstream bout = new bytearrayoutputstream();
        deroutputstream asn1out;
        if (usederencoding)
        {
            asn1out = new deroutputstream(bout);
        }
        else
        {
            asn1out = new beroutputstream(bout);
        }

        asn1out.writeobject(auth);

        byte[] pkg = bout.tobytearray();

        contentinfo maininfo = new contentinfo(data, new beroctetstring(pkg));

        //
        // create the mac
        //
        byte[] msalt = new byte[20];
        int itcount = min_iterations;

        random.nextbytes(msalt);

        byte[] data = ((asn1octetstring)maininfo.getcontent()).getoctets();

        macdata mdata;

        try
        {
            byte[] res = calculatepbemac(id_sha1, msalt, itcount, password, false, data);

            algorithmidentifier algid = new algorithmidentifier(id_sha1, dernull.instance);
            digestinfo dinfo = new digestinfo(algid, res);

            mdata = new macdata(dinfo, msalt, itcount);
        }
        catch (exception e)
        {
            throw new ioexception("error constructing mac: " + e.tostring());
        }

        //
        // output the pfx
        //
        pfx pfx = new pfx(maininfo, mdata);

        if (usederencoding)
        {
            asn1out = new deroutputstream(stream);
        }
        else
        {
            asn1out = new beroutputstream(stream);
        }

        asn1out.writeobject(pfx);
    }

    private static byte[] calculatepbemac(
        asn1objectidentifier oid,
        byte[] salt,
        int itcount,
        char[] password,
        boolean wrongpkcs12zero,
        byte[] data)
        throws exception
    {
        secretkeyfactory keyfact = secretkeyfactory.getinstance(oid.getid(), bcprovider);
        pbeparameterspec defparams = new pbeparameterspec(salt, itcount);
        pbekeyspec pbespec = new pbekeyspec(password);
        bcpbekey key = (bcpbekey)keyfact.generatesecret(pbespec);
        key.settrywrongpkcs12zero(wrongpkcs12zero);

        mac mac = mac.getinstance(oid.getid(), bcprovider);
        mac.init(key, defparams);
        mac.update(data);
        return mac.dofinal();
    }

    public static class bcpkcs12keystore
        extends pkcs12keystorespi
    {
        public bcpkcs12keystore()
        {
            super(bcprovider, pbewithshaand3_keytripledes_cbc, pbewithshaand40bitrc2_cbc);
        }
    }

    public static class bcpkcs12keystore3des
        extends pkcs12keystorespi
    {
        public bcpkcs12keystore3des()
        {
            super(bcprovider, pbewithshaand3_keytripledes_cbc, pbewithshaand3_keytripledes_cbc);
        }
    }

    public static class defpkcs12keystore
        extends pkcs12keystorespi
    {
        public defpkcs12keystore()
        {
            super(null, pbewithshaand3_keytripledes_cbc, pbewithshaand40bitrc2_cbc);
        }
    }

    public static class defpkcs12keystore3des
        extends pkcs12keystorespi
    {
        public defpkcs12keystore3des()
        {
            super(null, pbewithshaand3_keytripledes_cbc, pbewithshaand3_keytripledes_cbc);
        }
    }

    private static class ignorescasehashtable
    {
        private hashtable orig = new hashtable();
        private hashtable keys = new hashtable();

        public void put(string key, object value)
        {
            string lower = (key == null) ? null : strings.tolowercase(key);
            string k = (string)keys.get(lower);
            if (k != null)
            {
                orig.remove(k);
            }

            keys.put(lower, key);
            orig.put(key, value);
        }

        public enumeration keys()
        {
            return orig.keys();
        }

        public object remove(string alias)
        {
            string k = (string)keys.remove(alias == null ? null : strings.tolowercase(alias));
            if (k == null)
            {
                return null;
            }

            return orig.remove(k);
        }

        public object get(string alias)
        {
            string k = (string)keys.get(alias == null ? null : strings.tolowercase(alias));
            if (k == null)
            {
                return null;
            }

            return orig.get(k);
        }

        public enumeration elements()
        {
            return orig.elements();
        }
    }
}
