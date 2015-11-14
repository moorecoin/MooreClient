package org.ripple.bouncycastle.jcajce.provider.asymmetric.ec;

import java.math.biginteger;
import java.security.invalidalgorithmparameterexception;
import java.security.invalidkeyexception;
import java.security.key;
import java.security.nosuchalgorithmexception;
import java.security.privatekey;
import java.security.publickey;
import java.security.securerandom;
import java.security.spec.algorithmparameterspec;
import java.util.hashtable;

import javax.crypto.secretkey;
import javax.crypto.shortbufferexception;
import javax.crypto.spec.secretkeyspec;

import org.ripple.bouncycastle.asn1.derobjectidentifier;
import org.ripple.bouncycastle.asn1.nist.nistobjectidentifiers;
import org.ripple.bouncycastle.asn1.pkcs.pkcsobjectidentifiers;
import org.ripple.bouncycastle.asn1.x9.x9integerconverter;
import org.ripple.bouncycastle.crypto.basicagreement;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.derivationfunction;
import org.ripple.bouncycastle.crypto.agreement.ecdhbasicagreement;
import org.ripple.bouncycastle.crypto.agreement.ecdhcbasicagreement;
import org.ripple.bouncycastle.crypto.agreement.ecmqvbasicagreement;
import org.ripple.bouncycastle.crypto.agreement.kdf.dhkdfparameters;
import org.ripple.bouncycastle.crypto.agreement.kdf.ecdhkekgenerator;
import org.ripple.bouncycastle.crypto.digests.sha1digest;
import org.ripple.bouncycastle.crypto.params.ecdomainparameters;
import org.ripple.bouncycastle.crypto.params.ecprivatekeyparameters;
import org.ripple.bouncycastle.crypto.params.ecpublickeyparameters;
import org.ripple.bouncycastle.crypto.params.mqvprivateparameters;
import org.ripple.bouncycastle.crypto.params.mqvpublicparameters;
import org.ripple.bouncycastle.jcajce.provider.asymmetric.util.ecutil;
import org.ripple.bouncycastle.jce.interfaces.ecprivatekey;
import org.ripple.bouncycastle.jce.interfaces.ecpublickey;
import org.ripple.bouncycastle.jce.interfaces.mqvprivatekey;
import org.ripple.bouncycastle.jce.interfaces.mqvpublickey;
import org.ripple.bouncycastle.util.integers;

/**
 * diffie-hellman key agreement using elliptic curve keys, ala ieee p1363
 * both the simple one, and the simple one with cofactors are supported.
 *
 * also, mqv key agreement per sec-1
 */
public class keyagreementspi
    extends javax.crypto.keyagreementspi
{
    private static final x9integerconverter converter = new x9integerconverter();
    private static final hashtable algorithms = new hashtable();

    static
    {
        integer i128 = integers.valueof(128);
        integer i192 = integers.valueof(192);
        integer i256 = integers.valueof(256);

        algorithms.put(nistobjectidentifiers.id_aes128_cbc.getid(), i128);
        algorithms.put(nistobjectidentifiers.id_aes192_cbc.getid(), i192);
        algorithms.put(nistobjectidentifiers.id_aes256_cbc.getid(), i256);
        algorithms.put(nistobjectidentifiers.id_aes128_wrap.getid(), i128);
        algorithms.put(nistobjectidentifiers.id_aes192_wrap.getid(), i192);
        algorithms.put(nistobjectidentifiers.id_aes256_wrap.getid(), i256);
        algorithms.put(pkcsobjectidentifiers.id_alg_cms3deswrap.getid(), i192);
    }

    private string                 kaalgorithm;
    private biginteger             result;
    private ecdomainparameters     parameters;
    private basicagreement         agreement;
    private derivationfunction     kdf;

    private byte[] biginttobytes(
        biginteger    r)
    {
        return converter.integertobytes(r, converter.getbytelength(parameters.getg().getx()));
    }

    protected keyagreementspi(
        string kaalgorithm,
        basicagreement agreement,
        derivationfunction kdf)
    {
        this.kaalgorithm = kaalgorithm;
        this.agreement = agreement;
        this.kdf = kdf;
    }

    protected key enginedophase(
        key     key,
        boolean lastphase) 
        throws invalidkeyexception, illegalstateexception
    {
        if (parameters == null)
        {
            throw new illegalstateexception(kaalgorithm + " not initialised.");
        }

        if (!lastphase)
        {
            throw new illegalstateexception(kaalgorithm + " can only be between two parties.");
        }

        cipherparameters pubkey;        
        if (agreement instanceof ecmqvbasicagreement)
        {
            if (!(key instanceof mqvpublickey))
            {
                throw new invalidkeyexception(kaalgorithm + " key agreement requires "
                    + getsimplename(mqvpublickey.class) + " for dophase");
            }

            mqvpublickey mqvpubkey = (mqvpublickey)key;
            ecpublickeyparameters statickey = (ecpublickeyparameters)
                ecutil.generatepublickeyparameter(mqvpubkey.getstatickey());
            ecpublickeyparameters ephemkey = (ecpublickeyparameters)
                ecutil.generatepublickeyparameter(mqvpubkey.getephemeralkey());

            pubkey = new mqvpublicparameters(statickey, ephemkey);

            // todo validate that all the keys are using the same parameters?
        }
        else
        {
            if (!(key instanceof publickey))
            {
                throw new invalidkeyexception(kaalgorithm + " key agreement requires "
                    + getsimplename(ecpublickey.class) + " for dophase");
            }

            pubkey = ecutil.generatepublickeyparameter((publickey)key);

            // todo validate that all the keys are using the same parameters?
        }

        result = agreement.calculateagreement(pubkey);

        return null;
    }

    protected byte[] enginegeneratesecret()
        throws illegalstateexception
    {
        if (kdf != null)
        {
            throw new unsupportedoperationexception(
                "kdf can only be used when algorithm is known");
        }

        return biginttobytes(result);
    }

    protected int enginegeneratesecret(
        byte[]  sharedsecret,
        int     offset) 
        throws illegalstateexception, shortbufferexception
    {
        byte[] secret = enginegeneratesecret();

        if (sharedsecret.length - offset < secret.length)
        {
            throw new shortbufferexception(kaalgorithm + " key agreement: need " + secret.length + " bytes");
        }

        system.arraycopy(secret, 0, sharedsecret, offset, secret.length);
        
        return secret.length;
    }

    protected secretkey enginegeneratesecret(
        string algorithm)
        throws nosuchalgorithmexception
    {
        byte[] secret = biginttobytes(result);

        if (kdf != null)
        {
            if (!algorithms.containskey(algorithm))
            {
                throw new nosuchalgorithmexception("unknown algorithm encountered: " + algorithm);
            }
            
            int    keysize = ((integer)algorithms.get(algorithm)).intvalue();

            dhkdfparameters params = new dhkdfparameters(new derobjectidentifier(algorithm), keysize, secret);

            byte[] keybytes = new byte[keysize / 8];
            kdf.init(params);
            kdf.generatebytes(keybytes, 0, keybytes.length);
            secret = keybytes;
        }
        else
        {
            // todo should we be ensuring the key is the right length?
        }

        return new secretkeyspec(secret, algorithm);
    }

    protected void engineinit(
        key                     key,
        algorithmparameterspec  params,
        securerandom            random) 
        throws invalidkeyexception, invalidalgorithmparameterexception
    {
        initfromkey(key);
    }

    protected void engineinit(
        key             key,
        securerandom    random) 
        throws invalidkeyexception
    {
        initfromkey(key);
    }

    private void initfromkey(key key)
        throws invalidkeyexception
    {
        if (agreement instanceof ecmqvbasicagreement)
        {
            if (!(key instanceof mqvprivatekey))
            {
                throw new invalidkeyexception(kaalgorithm + " key agreement requires "
                    + getsimplename(mqvprivatekey.class) + " for initialisation");
            }

            mqvprivatekey mqvprivkey = (mqvprivatekey)key;
            ecprivatekeyparameters staticprivkey = (ecprivatekeyparameters)
                ecutil.generateprivatekeyparameter(mqvprivkey.getstaticprivatekey());
            ecprivatekeyparameters ephemprivkey = (ecprivatekeyparameters)
                ecutil.generateprivatekeyparameter(mqvprivkey.getephemeralprivatekey());

            ecpublickeyparameters ephempubkey = null;
            if (mqvprivkey.getephemeralpublickey() != null)
            {
                ephempubkey = (ecpublickeyparameters)
                    ecutil.generatepublickeyparameter(mqvprivkey.getephemeralpublickey());
            }

            mqvprivateparameters localparams = new mqvprivateparameters(staticprivkey, ephemprivkey, ephempubkey);
            this.parameters = staticprivkey.getparameters();

            // todo validate that all the keys are using the same parameters?

            agreement.init(localparams);
        }
        else
        {
            if (!(key instanceof privatekey))
            {
                throw new invalidkeyexception(kaalgorithm + " key agreement requires "
                    + getsimplename(ecprivatekey.class) + " for initialisation");
            }

            ecprivatekeyparameters privkey = (ecprivatekeyparameters)ecutil.generateprivatekeyparameter((privatekey)key);
            this.parameters = privkey.getparameters();

            agreement.init(privkey);
        }
    }

    private static string getsimplename(class clazz)
    {
        string fullname = clazz.getname();

        return fullname.substring(fullname.lastindexof('.') + 1);
    }

    public static class dh
        extends keyagreementspi
    {
        public dh()
        {
            super("ecdh", new ecdhbasicagreement(), null);
        }
    }

    public static class dhc
        extends keyagreementspi
    {
        public dhc()
        {
            super("ecdhc", new ecdhcbasicagreement(), null);
        }
    }

    public static class mqv
        extends keyagreementspi
    {
        public mqv()
        {
            super("ecmqv", new ecmqvbasicagreement(), null);
        }
    }

    public static class dhwithsha1kdf
        extends keyagreementspi
    {
        public dhwithsha1kdf()
        {
            super("ecdhwithsha1kdf", new ecdhbasicagreement(), new ecdhkekgenerator(new sha1digest()));
        }
    }

    public static class mqvwithsha1kdf
        extends keyagreementspi
    {
        public mqvwithsha1kdf()
        {
            super("ecmqvwithsha1kdf", new ecmqvbasicagreement(), new ecdhkekgenerator(new sha1digest()));
        }
    }
}
