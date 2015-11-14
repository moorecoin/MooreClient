package org.ripple.bouncycastle.jcajce.provider.asymmetric.gost;

import java.math.biginteger;
import java.security.invalidkeyexception;
import java.security.privatekey;
import java.security.publickey;
import java.security.securerandom;
import java.security.signatureexception;
import java.security.spec.algorithmparameterspec;

import org.ripple.bouncycastle.asn1.pkcs.pkcsobjectidentifiers;
import org.ripple.bouncycastle.asn1.x509.subjectpublickeyinfo;
import org.ripple.bouncycastle.asn1.x509.x509objectidentifiers;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.dsa;
import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.crypto.digests.gost3411digest;
import org.ripple.bouncycastle.crypto.params.parameterswithrandom;
import org.ripple.bouncycastle.crypto.signers.gost3410signer;
import org.ripple.bouncycastle.jcajce.provider.asymmetric.util.ecutil;
import org.ripple.bouncycastle.jcajce.provider.asymmetric.util.gost3410util;
import org.ripple.bouncycastle.jce.interfaces.eckey;
import org.ripple.bouncycastle.jce.interfaces.ecpublickey;
import org.ripple.bouncycastle.jce.interfaces.gost3410key;
import org.ripple.bouncycastle.jce.provider.bouncycastleprovider;

public class signaturespi
    extends java.security.signaturespi
    implements pkcsobjectidentifiers, x509objectidentifiers
{
    private digest                  digest;
    private dsa                     signer;
    private securerandom            random;

    public signaturespi()
    {
        this.digest = new gost3411digest();
        this.signer = new gost3410signer();
    }

    protected void engineinitverify(
        publickey   publickey)
        throws invalidkeyexception
    {
        cipherparameters    param;

        if (publickey instanceof ecpublickey)
        {
            param = ecutil.generatepublickeyparameter(publickey);
        }
        else if (publickey instanceof gost3410key)
        {
            param = gost3410util.generatepublickeyparameter(publickey);
        }
        else
        {
            try
            {
                byte[]  bytes = publickey.getencoded();

                publickey = bouncycastleprovider.getpublickey(subjectpublickeyinfo.getinstance(bytes));

                if (publickey instanceof ecpublickey)
                {
                    param = ecutil.generatepublickeyparameter(publickey);
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

        if (privatekey instanceof eckey)
        {
            param = ecutil.generateprivatekeyparameter(privatekey);
        }
        else
        {
            param = gost3410util.generateprivatekeyparameter(privatekey);
        }

        digest.reset();

        if (random != null)
        {
            signer.init(true, new parameterswithrandom(param, random));
        }
        else
        {
            signer.init(true, param);
        }
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
            byte[]          sigbytes = new byte[64];
            biginteger[]    sig = signer.generatesignature(hash);
            byte[]          r = sig[0].tobytearray();
            byte[]          s = sig[1].tobytearray();

            if (s[0] != 0)
            {
                system.arraycopy(s, 0, sigbytes, 32 - s.length, s.length);
            }
            else
            {
                system.arraycopy(s, 1, sigbytes, 32 - (s.length - 1), s.length - 1);
            }
            
            if (r[0] != 0)
            {
                system.arraycopy(r, 0, sigbytes, 64 - r.length, r.length);
            }
            else
            {
                system.arraycopy(r, 1, sigbytes, 64 - (r.length - 1), r.length - 1);
            }

            return sigbytes;
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
            byte[] r = new byte[32]; 
            byte[] s = new byte[32];

            system.arraycopy(sigbytes, 0, s, 0, 32);

            system.arraycopy(sigbytes, 32, r, 0, 32);
            
            sig = new biginteger[2];
            sig[0] = new biginteger(1, r);
            sig[1] = new biginteger(1, s);
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
}
