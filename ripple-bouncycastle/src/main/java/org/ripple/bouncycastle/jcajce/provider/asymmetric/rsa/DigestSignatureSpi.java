package org.ripple.bouncycastle.jcajce.provider.asymmetric.rsa;

import java.io.ioexception;
import java.security.algorithmparameters;
import java.security.invalidkeyexception;
import java.security.privatekey;
import java.security.publickey;
import java.security.signatureexception;
import java.security.signaturespi;
import java.security.interfaces.rsaprivatekey;
import java.security.interfaces.rsapublickey;
import java.security.spec.algorithmparameterspec;

import org.ripple.bouncycastle.asn1.asn1encoding;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.dernull;
import org.ripple.bouncycastle.asn1.nist.nistobjectidentifiers;
import org.ripple.bouncycastle.asn1.oiw.oiwobjectidentifiers;
import org.ripple.bouncycastle.asn1.pkcs.pkcsobjectidentifiers;
import org.ripple.bouncycastle.asn1.teletrust.teletrustobjectidentifiers;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;
import org.ripple.bouncycastle.asn1.x509.digestinfo;
import org.ripple.bouncycastle.crypto.asymmetricblockcipher;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.crypto.digests.md2digest;
import org.ripple.bouncycastle.crypto.digests.md4digest;
import org.ripple.bouncycastle.crypto.digests.md5digest;
import org.ripple.bouncycastle.crypto.digests.nulldigest;
import org.ripple.bouncycastle.crypto.digests.ripemd128digest;
import org.ripple.bouncycastle.crypto.digests.ripemd160digest;
import org.ripple.bouncycastle.crypto.digests.ripemd256digest;
import org.ripple.bouncycastle.crypto.digests.sha1digest;
import org.ripple.bouncycastle.crypto.digests.sha224digest;
import org.ripple.bouncycastle.crypto.digests.sha256digest;
import org.ripple.bouncycastle.crypto.digests.sha384digest;
import org.ripple.bouncycastle.crypto.digests.sha512digest;
import org.ripple.bouncycastle.crypto.encodings.pkcs1encoding;
import org.ripple.bouncycastle.crypto.engines.rsablindedengine;

public class digestsignaturespi
    extends signaturespi
{
    private digest digest;
    private asymmetricblockcipher cipher;
    private algorithmidentifier algid;

    // care - this constructor is actually used by outside organisations
    protected digestsignaturespi(
        digest digest,
        asymmetricblockcipher cipher)
    {
        this.digest = digest;
        this.cipher = cipher;
        this.algid = null;
    }

    // care - this constructor is actually used by outside organisations
    protected digestsignaturespi(
        asn1objectidentifier objid,
        digest digest,
        asymmetricblockcipher cipher)
    {
        this.digest = digest;
        this.cipher = cipher;
        this.algid = new algorithmidentifier(objid, dernull.instance);
    }

    protected void engineinitverify(
        publickey publickey)
        throws invalidkeyexception
    {
        if (!(publickey instanceof rsapublickey))
        {
            throw new invalidkeyexception("supplied key (" + gettype(publickey) + ") is not a rsapublickey instance");
        }

        cipherparameters param = rsautil.generatepublickeyparameter((rsapublickey)publickey);

        digest.reset();
        cipher.init(false, param);
    }

    protected void engineinitsign(
        privatekey privatekey)
        throws invalidkeyexception
    {
        if (!(privatekey instanceof rsaprivatekey))
        {
            throw new invalidkeyexception("supplied key (" + gettype(privatekey) + ") is not a rsaprivatekey instance");
        }

        cipherparameters param = rsautil.generateprivatekeyparameter((rsaprivatekey)privatekey);

        digest.reset();

        cipher.init(true, param);
    }

    private string gettype(
        object o)
    {
        if (o == null)
        {
            return null;
        }
        
        return o.getclass().getname();
    }
    
    protected void engineupdate(
        byte    b)
        throws signatureexception
    {
        digest.update(b);
    }

    protected void engineupdate(
        byte[]  b,
        int     off,
        int     len) 
        throws signatureexception
    {
        digest.update(b, off, len);
    }

    protected byte[] enginesign()
        throws signatureexception
    {
        byte[]  hash = new byte[digest.getdigestsize()];

        digest.dofinal(hash, 0);

        try
        {
            byte[]  bytes = derencode(hash);

            return cipher.processblock(bytes, 0, bytes.length);
        }
        catch (arrayindexoutofboundsexception e)
        {
            throw new signatureexception("key too small for signature type");
        }
        catch (exception e)
        {
            throw new signatureexception(e.tostring());
        }
    }

    protected boolean engineverify(
        byte[]  sigbytes) 
        throws signatureexception
    {
        byte[]  hash = new byte[digest.getdigestsize()];

        digest.dofinal(hash, 0);

        byte[]      sig;
        byte[]      expected;

        try
        {
            sig = cipher.processblock(sigbytes, 0, sigbytes.length);

            expected = derencode(hash);
        }
        catch (exception e)
        {
            return false;
        }

        if (sig.length == expected.length)
        {
            for (int i = 0; i < sig.length; i++)
            {
                if (sig[i] != expected[i])
                {
                    return false;
                }
            }
        }
        else if (sig.length == expected.length - 2)  // null left out
        {
            int sigoffset = sig.length - hash.length - 2;
            int expectedoffset = expected.length - hash.length - 2;

            expected[1] -= 2;      // adjust lengths
            expected[3] -= 2;

            for (int i = 0; i < hash.length; i++)
            {
                if (sig[sigoffset + i] != expected[expectedoffset + i])  // check hash
                {
                    return false;
                }
            }

            for (int i = 0; i < sigoffset; i++)
            {
                if (sig[i] != expected[i])  // check header less null
                {
                    return false;
                }
            }
        }
        else
        {
            return false;
        }

        return true;
    }

    protected void enginesetparameter(
        algorithmparameterspec params)
    {
        throw new unsupportedoperationexception("enginesetparameter unsupported");
    }

    /**
     * @deprecated replaced with <a href = "#enginesetparameter(java.security.spec.algorithmparameterspec)">
     */
    protected void enginesetparameter(
        string param,
        object value)
    {
        throw new unsupportedoperationexception("enginesetparameter unsupported");
    }

    /**
     * @deprecated
     */
    protected object enginegetparameter(
        string param)
    {
        return null;
    }

    protected algorithmparameters enginegetparameters()
    {
        return null;
    }

    private byte[] derencode(
        byte[]  hash)
        throws ioexception
    {
        if (algid == null)
        {
            // for raw rsa, the digestinfo must be prepared externally
            return hash;
        }

        digestinfo dinfo = new digestinfo(algid, hash);

        return dinfo.getencoded(asn1encoding.der);
    }

    static public class sha1
        extends digestsignaturespi
    {
        public sha1()
        {
            super(oiwobjectidentifiers.idsha1, new sha1digest(), new pkcs1encoding(new rsablindedengine()));
        }
    }

    static public class sha224
        extends digestsignaturespi
    {
        public sha224()
        {
            super(nistobjectidentifiers.id_sha224, new sha224digest(), new pkcs1encoding(new rsablindedengine()));
        }
    }

    static public class sha256
        extends digestsignaturespi
    {
        public sha256()
        {
            super(nistobjectidentifiers.id_sha256, new sha256digest(), new pkcs1encoding(new rsablindedengine()));
        }
    }

    static public class sha384
        extends digestsignaturespi
    {
        public sha384()
        {
            super(nistobjectidentifiers.id_sha384, new sha384digest(), new pkcs1encoding(new rsablindedengine()));
        }
    }

    static public class sha512
        extends digestsignaturespi
    {
        public sha512()
        {
            super(nistobjectidentifiers.id_sha512, new sha512digest(), new pkcs1encoding(new rsablindedengine()));
        }
    }

    static public class md2
        extends digestsignaturespi
    {
        public md2()
        {
            super(pkcsobjectidentifiers.md2, new md2digest(), new pkcs1encoding(new rsablindedengine()));
        }
    }

    static public class md4
        extends digestsignaturespi
    {
        public md4()
        {
            super(pkcsobjectidentifiers.md4, new md4digest(), new pkcs1encoding(new rsablindedengine()));
        }
    }

    static public class md5
        extends digestsignaturespi
    {
        public md5()
        {
            super(pkcsobjectidentifiers.md5, new md5digest(), new pkcs1encoding(new rsablindedengine()));
        }
    }

    static public class ripemd160
        extends digestsignaturespi
    {
        public ripemd160()
        {
            super(teletrustobjectidentifiers.ripemd160, new ripemd160digest(), new pkcs1encoding(new rsablindedengine()));
        }
    }

    static public class ripemd128
        extends digestsignaturespi
    {
        public ripemd128()
        {
            super(teletrustobjectidentifiers.ripemd128, new ripemd128digest(), new pkcs1encoding(new rsablindedengine()));
        }
    }

    static public class ripemd256
        extends digestsignaturespi
    {
        public ripemd256()
        {
            super(teletrustobjectidentifiers.ripemd256, new ripemd256digest(), new pkcs1encoding(new rsablindedengine()));
        }
    }

    static public class nonersa
        extends digestsignaturespi
    {
        public nonersa()
        {
            super(new nulldigest(), new pkcs1encoding(new rsablindedengine()));
        }
    }
}
