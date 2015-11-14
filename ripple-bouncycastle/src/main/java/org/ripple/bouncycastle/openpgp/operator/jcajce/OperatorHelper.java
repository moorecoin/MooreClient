package org.ripple.bouncycastle.openpgp.operator.jcajce;

import java.io.inputstream;
import java.security.generalsecurityexception;
import java.security.keyfactory;
import java.security.messagedigest;
import java.security.signature;

import javax.crypto.cipher;
import javax.crypto.cipherinputstream;
import javax.crypto.secretkey;
import javax.crypto.spec.ivparameterspec;
import javax.crypto.spec.secretkeyspec;

import org.ripple.bouncycastle.bcpg.publickeyalgorithmtags;
import org.ripple.bouncycastle.jcajce.jcajcehelper;
import org.ripple.bouncycastle.openpgp.pgpexception;
import org.ripple.bouncycastle.openpgp.pgppublickey;
import org.ripple.bouncycastle.openpgp.operator.pgpdatadecryptor;
import org.ripple.bouncycastle.openpgp.operator.pgpdigestcalculator;

class operatorhelper
{
    private jcajcehelper helper;

    operatorhelper(jcajcehelper helper)
    {
        this.helper = helper;
    }

    messagedigest createdigest(int algorithm)
        throws generalsecurityexception, pgpexception
    {
        messagedigest dig;

        dig = helper.createdigest(pgputil.getdigestname(algorithm));

        return dig;
    }

    keyfactory createkeyfactory(string algorithm)
        throws generalsecurityexception, pgpexception
    {
        return helper.createkeyfactory(algorithm);
    }

    pgpdatadecryptor createdatadecryptor(boolean withintegritypacket, int encalgorithm, byte[] key)
        throws pgpexception
    {
        try
        {
            secretkey secretkey = new secretkeyspec(key, pgputil.getsymmetricciphername(encalgorithm));

            final cipher c = createstreamcipher(encalgorithm, withintegritypacket);

            byte[] iv = new byte[c.getblocksize()];

            c.init(cipher.decrypt_mode, secretkey, new ivparameterspec(iv));

            return new pgpdatadecryptor()
            {
                public inputstream getinputstream(inputstream in)
                {
                    return new cipherinputstream(in, c);
                }

                public int getblocksize()
                {
                    return c.getblocksize();
                }

                public pgpdigestcalculator getintegritycalculator()
                {
                    return new sha1pgpdigestcalculator();
                }
            };
        }
        catch (pgpexception e)
        {
            throw e;
        }
        catch (exception e)
        {
            throw new pgpexception("exception creating cipher", e);
        }
    }

    cipher createstreamcipher(int encalgorithm, boolean withintegritypacket)
        throws pgpexception
    {
        string mode = (withintegritypacket)
            ? "cfb"
            : "openpgpcfb";

        string cname = pgputil.getsymmetricciphername(encalgorithm)
            + "/" + mode + "/nopadding";

        return createcipher(cname);
    }

    cipher createcipher(string ciphername)
        throws pgpexception
    {
        try
        {
            return helper.createcipher(ciphername);
        }
        catch (generalsecurityexception e)
        {
            throw new pgpexception("cannot create cipher: " + e.getmessage(), e);
        }
    }

    cipher createpublickeycipher(int encalgorithm)
        throws pgpexception
    {
        switch (encalgorithm)
        {
        case pgppublickey.rsa_encrypt:
        case pgppublickey.rsa_general:
            return createcipher("rsa/ecb/pkcs1padding");
        case pgppublickey.elgamal_encrypt:
        case pgppublickey.elgamal_general:
            return createcipher("elgamal/ecb/pkcs1padding");
        case pgppublickey.dsa:
            throw new pgpexception("can't use dsa for encryption.");
        case pgppublickey.ecdsa:
            throw new pgpexception("can't use ecdsa for encryption.");
        default:
            throw new pgpexception("unknown asymmetric algorithm: " + encalgorithm);
        }
    }

    private signature createsignature(string ciphername)
        throws pgpexception
    {
        try
        {
            return helper.createsignature(ciphername);
        }
        catch (generalsecurityexception e)
        {
            throw new pgpexception("cannot create signature: " + e.getmessage(), e);
        }
    }

    public signature createsignature(int keyalgorithm, int hashalgorithm)
        throws pgpexception
    {
        string     encalg;

        switch (keyalgorithm)
        {
        case publickeyalgorithmtags.rsa_general:
        case publickeyalgorithmtags.rsa_sign:
            encalg = "rsa";
            break;
        case publickeyalgorithmtags.dsa:
            encalg = "dsa";
            break;
        case publickeyalgorithmtags.elgamal_encrypt: // in some malformed cases.
        case publickeyalgorithmtags.elgamal_general:
            encalg = "elgamal";
            break;
        default:
            throw new pgpexception("unknown algorithm tag in signature:" + keyalgorithm);
        }

        return createsignature(pgputil.getdigestname(hashalgorithm) + "with" + encalg);
    }
}
