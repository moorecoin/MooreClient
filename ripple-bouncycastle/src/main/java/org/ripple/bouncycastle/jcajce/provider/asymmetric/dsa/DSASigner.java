package org.ripple.bouncycastle.jcajce.provider.asymmetric.dsa;

import java.io.ioexception;
import java.math.biginteger;
import java.security.invalidkeyexception;
import java.security.privatekey;
import java.security.publickey;
import java.security.securerandom;
import java.security.signatureexception;
import java.security.signaturespi;
import java.security.interfaces.dsakey;
import java.security.spec.algorithmparameterspec;

import org.ripple.bouncycastle.asn1.asn1encoding;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.pkcs.pkcsobjectidentifiers;
import org.ripple.bouncycastle.asn1.x509.subjectpublickeyinfo;
import org.ripple.bouncycastle.asn1.x509.x509objectidentifiers;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.dsa;
import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.crypto.digests.nulldigest;
import org.ripple.bouncycastle.crypto.digests.sha1digest;
import org.ripple.bouncycastle.crypto.digests.sha224digest;
import org.ripple.bouncycastle.crypto.digests.sha256digest;
import org.ripple.bouncycastle.crypto.digests.sha384digest;
import org.ripple.bouncycastle.crypto.digests.sha512digest;
import org.ripple.bouncycastle.crypto.params.parameterswithrandom;

public class dsasigner
    extends signaturespi
    implements pkcsobjectidentifiers, x509objectidentifiers
{
    private digest                  digest;
    private dsa                     signer;
    private securerandom            random;

    protected dsasigner(
        digest digest,
        dsa signer)
    {
        this.digest = digest;
        this.signer = signer;
    }

    protected void engineinitverify(
        publickey   publickey)
        throws invalidkeyexception
    {
        cipherparameters    param;

        if (publickey instanceof dsakey)
        {
            param = dsautil.generatepublickeyparameter(publickey);
        }
        else
        {
            try
            {
                byte[]  bytes = publickey.getencoded();

                publickey = new bcdsapublickey(subjectpublickeyinfo.getinstance(bytes));

                if (publickey instanceof dsakey)
                {
                    param = dsautil.generatepublickeyparameter(publickey);
                }
                else
                {
                    throw new invalidkeyexception("can't recognise key type in dsa based signer");
                }
            }
            catch (exception e)
            {
                throw new invalidkeyexception("can't recognise key type in dsa based signer");
            }
        }

        digest.reset();
        signer.init(false, param);
    }

    protected void engineinitsign(
        privatekey      privatekey,
        securerandom    random)
        throws invalidkeyexception
    {
        this.random = random;
        engineinitsign(privatekey);
    }

    protected void engineinitsign(
        privatekey  privatekey)
        throws invalidkeyexception
    {
        cipherparameters    param;

        param = dsautil.generateprivatekeyparameter(privatekey);

        if (random != null)
        {
            param = new parameterswithrandom(param, random);
        }

        digest.reset();
        signer.init(true, param);
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
            biginteger[]    sig = signer.generatesignature(hash);

            return derencode(sig[0], sig[1]);
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

        biginteger[]    sig;

        try
        {
            sig = derdecode(sigbytes);
        }
        catch (exception e)
        {
            throw new signatureexception("error decoding signature bytes.");
        }

        return signer.verifysignature(hash, sig[0], sig[1]);
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
        string  param,
        object  value)
    {
        throw new unsupportedoperationexception("enginesetparameter unsupported");
    }

    /**
     * @deprecated
     */
    protected object enginegetparameter(
        string      param)
    {
        throw new unsupportedoperationexception("enginesetparameter unsupported");
    }

    private byte[] derencode(
        biginteger  r,
        biginteger  s)
        throws ioexception
    {
        asn1integer[] rs = new asn1integer[]{ new asn1integer(r), new asn1integer(s) };
        return new dersequence(rs).getencoded(asn1encoding.der);
    }

    private biginteger[] derdecode(
        byte[]  encoding)
        throws ioexception
    {
        asn1sequence s = (asn1sequence)asn1primitive.frombytearray(encoding);
        return new biginteger[]{
            ((asn1integer)s.getobjectat(0)).getvalue(),
            ((asn1integer)s.getobjectat(1)).getvalue()
        };
    }

    static public class stddsa
        extends dsasigner
    {
        public stddsa()
        {
            super(new sha1digest(), new org.ripple.bouncycastle.crypto.signers.dsasigner());
        }
    }

    static public class dsa224
        extends dsasigner
    {
        public dsa224()
        {
            super(new sha224digest(), new org.ripple.bouncycastle.crypto.signers.dsasigner());
        }
    }
    
    static public class dsa256
        extends dsasigner
    {
        public dsa256()
        {
            super(new sha256digest(), new org.ripple.bouncycastle.crypto.signers.dsasigner());
        }
    }
    
    static public class dsa384
        extends dsasigner
    {
        public dsa384()
        {
            super(new sha384digest(), new org.ripple.bouncycastle.crypto.signers.dsasigner());
        }
    }
    
    static public class dsa512
        extends dsasigner
    {
        public dsa512()
        {
            super(new sha512digest(), new org.ripple.bouncycastle.crypto.signers.dsasigner());
        }
    }

    static public class nonedsa
        extends dsasigner
    {
        public nonedsa()
        {
            super(new nulldigest(), new org.ripple.bouncycastle.crypto.signers.dsasigner());
        }
    }
}
