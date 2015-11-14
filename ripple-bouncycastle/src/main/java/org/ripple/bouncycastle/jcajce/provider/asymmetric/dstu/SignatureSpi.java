package org.ripple.bouncycastle.jcajce.provider.asymmetric.dstu;

import java.math.biginteger;
import java.security.invalidkeyexception;
import java.security.privatekey;
import java.security.publickey;
import java.security.signatureexception;
import java.security.spec.algorithmparameterspec;

import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.deroctetstring;
import org.ripple.bouncycastle.asn1.pkcs.pkcsobjectidentifiers;
import org.ripple.bouncycastle.asn1.x509.subjectpublickeyinfo;
import org.ripple.bouncycastle.asn1.x509.x509objectidentifiers;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.dsa;
import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.crypto.digests.gost3411digest;
import org.ripple.bouncycastle.crypto.params.parameterswithrandom;
import org.ripple.bouncycastle.crypto.signers.dstu4145signer;
import org.ripple.bouncycastle.jcajce.provider.asymmetric.util.ecutil;
import org.ripple.bouncycastle.jce.interfaces.eckey;
import org.ripple.bouncycastle.jce.interfaces.ecpublickey;
import org.ripple.bouncycastle.jce.provider.bouncycastleprovider;

public class signaturespi
    extends java.security.signaturespi
    implements pkcsobjectidentifiers, x509objectidentifiers
{
    private digest digest;
    private dsa signer;

    private static byte[] default_sbox = {
        0xa, 0x9, 0xd, 0x6, 0xe, 0xb, 0x4, 0x5, 0xf, 0x1, 0x3, 0xc, 0x7, 0x0, 0x8, 0x2,
        0x8, 0x0, 0xc, 0x4, 0x9, 0x6, 0x7, 0xb, 0x2, 0x3, 0x1, 0xf, 0x5, 0xe, 0xa, 0xd,
        0xf, 0x6, 0x5, 0x8, 0xe, 0xb, 0xa, 0x4, 0xc, 0x0, 0x3, 0x7, 0x2, 0x9, 0x1, 0xd,
        0x3, 0x8, 0xd, 0x9, 0x6, 0xb, 0xf, 0x0, 0x2, 0x5, 0xc, 0xa, 0x4, 0xe, 0x1, 0x7,
        0xf, 0x8, 0xe, 0x9, 0x7, 0x2, 0x0, 0xd, 0xc, 0x6, 0x1, 0x5, 0xb, 0x4, 0x3, 0xa,
        0x2, 0x8, 0x9, 0x7, 0x5, 0xf, 0x0, 0xb, 0xc, 0x1, 0xd, 0xe, 0xa, 0x3, 0x6, 0x4,
        0x3, 0x8, 0xb, 0x5, 0x6, 0x4, 0xe, 0xa, 0x2, 0xc, 0x1, 0x7, 0x9, 0xf, 0xd, 0x0,
        0x1, 0x2, 0x3, 0xe, 0x6, 0xd, 0xb, 0x8, 0xf, 0xa, 0xc, 0x5, 0x7, 0x9, 0x0, 0x4
    };

    public signaturespi()
    {
        //todo: add default ua s-box
        //this.digest = new gost3411digest(default_sbox);
        this.signer = new dstu4145signer();
    }

    protected void engineinitverify(
        publickey publickey)
        throws invalidkeyexception
    {
        cipherparameters param;

        if (publickey instanceof ecpublickey)
        {
            param = ecutil.generatepublickeyparameter(publickey);
        }
        else
        {
            try
            {
                byte[] bytes = publickey.getencoded();

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

        digest = new gost3411digest(expandsbox(((bcdstu4145publickey)publickey).getsbox()));
        signer.init(false, param);
    }

    byte[] expandsbox(byte[] compressed)
    {
        byte[] expanded = new byte[128];

        for (int i = 0; i < compressed.length; i++)
        {
            expanded[i * 2] = (byte)((compressed[i] >> 4) & 0xf);
            expanded[i * 2 + 1] = (byte)(compressed[i] & 0xf);
        }
        return expanded;
    }

    protected void engineinitsign(
        privatekey privatekey)
        throws invalidkeyexception
    {
        cipherparameters param = null;

        if (privatekey instanceof eckey)
        {
            param = ecutil.generateprivatekeyparameter(privatekey);
        }

        digest = new gost3411digest(default_sbox);

        if (apprandom != null)
        {
            signer.init(true, new parameterswithrandom(param, apprandom));
        }
        else
        {
            signer.init(true, param);
        }
    }

    protected void engineupdate(
        byte b)
        throws signatureexception
    {
        digest.update(b);
    }

    protected void engineupdate(
        byte[] b,
        int off,
        int len)
        throws signatureexception
    {
        digest.update(b, off, len);
    }

    protected byte[] enginesign()
        throws signatureexception
    {
        byte[] hash = new byte[digest.getdigestsize()];

        digest.dofinal(hash, 0);

        try
        {
            biginteger[] sig = signer.generatesignature(hash);
            byte[] r = sig[0].tobytearray();
            byte[] s = sig[1].tobytearray();

            byte[] sigbytes = new byte[(r.length > s.length ? r.length * 2 : s.length * 2)];
            system.arraycopy(s, 0, sigbytes, (sigbytes.length / 2) - s.length, s.length);
            system.arraycopy(r, 0, sigbytes, sigbytes.length - r.length, r.length);

            return new deroctetstring(sigbytes).getencoded();
        }
        catch (exception e)
        {
            throw new signatureexception(e.tostring());
        }
    }

    protected boolean engineverify(
        byte[] sigbytes)
        throws signatureexception
    {
        byte[] hash = new byte[digest.getdigestsize()];

        digest.dofinal(hash, 0);

        biginteger[] sig;

        try
        {
            byte[] bytes = ((asn1octetstring)asn1octetstring.frombytearray(sigbytes)).getoctets();

            byte[] r = new byte[bytes.length / 2];
            byte[] s = new byte[bytes.length / 2];

            system.arraycopy(bytes, 0, s, 0, bytes.length / 2);

            system.arraycopy(bytes, bytes.length / 2, r, 0, bytes.length / 2);

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
        throw new unsupportedoperationexception("enginesetparameter unsupported");
    }
}
