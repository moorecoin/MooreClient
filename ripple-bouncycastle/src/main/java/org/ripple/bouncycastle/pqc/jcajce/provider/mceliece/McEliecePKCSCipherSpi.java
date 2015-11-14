package org.ripple.bouncycastle.pqc.jcajce.provider.mceliece;

import java.security.invalidalgorithmparameterexception;
import java.security.invalidkeyexception;
import java.security.key;
import java.security.privatekey;
import java.security.publickey;
import java.security.securerandom;
import java.security.spec.algorithmparameterspec;

import javax.crypto.badpaddingexception;
import javax.crypto.illegalblocksizeexception;

import org.ripple.bouncycastle.asn1.pkcs.pkcsobjectidentifiers;
import org.ripple.bouncycastle.asn1.x509.x509objectidentifiers;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.crypto.digests.sha1digest;
import org.ripple.bouncycastle.crypto.digests.sha224digest;
import org.ripple.bouncycastle.crypto.digests.sha256digest;
import org.ripple.bouncycastle.crypto.digests.sha384digest;
import org.ripple.bouncycastle.crypto.digests.sha512digest;
import org.ripple.bouncycastle.crypto.params.parameterswithrandom;
import org.ripple.bouncycastle.pqc.crypto.mceliece.mceliecekeyparameters;
import org.ripple.bouncycastle.pqc.crypto.mceliece.mceliecepkcscipher;
import org.ripple.bouncycastle.pqc.jcajce.provider.util.asymmetricblockcipher;

public class mceliecepkcscipherspi
    extends asymmetricblockcipher
    implements pkcsobjectidentifiers, x509objectidentifiers
{
    // todo digest needed?
    private digest digest;
    private mceliecepkcscipher cipher;

    public mceliecepkcscipherspi(digest digest, mceliecepkcscipher cipher)
    {
        this.digest = digest;
        this.cipher = cipher;
    }

    protected void initcipherencrypt(key key, algorithmparameterspec params,
                                     securerandom sr)
        throws invalidkeyexception,
        invalidalgorithmparameterexception
    {

        cipherparameters param;
        param = mceliecekeystoparams.generatepublickeyparameter((publickey)key);

        param = new parameterswithrandom(param, sr);
        digest.reset();
        cipher.init(true, param);
        this.maxplaintextsize = cipher.maxplaintextsize;
        this.ciphertextsize = cipher.ciphertextsize;
    }

    protected void initcipherdecrypt(key key, algorithmparameterspec params)
        throws invalidkeyexception, invalidalgorithmparameterexception
    {
        cipherparameters param;
        param = mceliecekeystoparams.generateprivatekeyparameter((privatekey)key);

        digest.reset();
        cipher.init(false, param);
        this.maxplaintextsize = cipher.maxplaintextsize;
        this.ciphertextsize = cipher.ciphertextsize;
    }

    protected byte[] messageencrypt(byte[] input)
        throws illegalblocksizeexception, badpaddingexception
    {
        byte[] output = null;
        try
        {
            output = cipher.messageencrypt(input);
        }
        catch (exception e)
        {
            e.printstacktrace();
        }
        return output;
    }

    protected byte[] messagedecrypt(byte[] input)
        throws illegalblocksizeexception, badpaddingexception
    {
        byte[] output = null;
        try
        {
            output = cipher.messagedecrypt(input);
        }
        catch (exception e)
        {
            e.printstacktrace();
        }
        return output;
    }

    public string getname()
    {
        return "mceliecepkcs";
    }

    public int getkeysize(key key)
        throws invalidkeyexception
    {
        mceliecekeyparameters mceliecekeyparameters;
        if (key instanceof publickey)
        {
            mceliecekeyparameters = (mceliecekeyparameters)mceliecekeystoparams.generatepublickeyparameter((publickey)key);
        }
        else
        {
            mceliecekeyparameters = (mceliecekeyparameters)mceliecekeystoparams.generateprivatekeyparameter((privatekey)key);

        }


        return cipher.getkeysize(mceliecekeyparameters);
    }

    //////////////////////////////////////////////////////////////////////////////////

    static public class mceliecepkcs
        extends mceliecepkcscipherspi
    {
        public mceliecepkcs()
        {
            super(new sha1digest(), new mceliecepkcscipher());
        }
    }

    static public class mceliecepkcs224
        extends mceliecepkcscipherspi
    {
        public mceliecepkcs224()
        {
            super(new sha224digest(), new mceliecepkcscipher());
        }
    }

    static public class mceliecepkcs256
        extends mceliecepkcscipherspi
    {
        public mceliecepkcs256()
        {
            super(new sha256digest(), new mceliecepkcscipher());
        }
    }

    static public class mceliecepkcs384
        extends mceliecepkcscipherspi
    {
        public mceliecepkcs384()
        {
            super(new sha384digest(), new mceliecepkcscipher());
        }
    }

    static public class mceliecepkcs512
        extends mceliecepkcscipherspi
    {
        public mceliecepkcs512()
        {
            super(new sha512digest(), new mceliecepkcscipher());
        }
    }


}
