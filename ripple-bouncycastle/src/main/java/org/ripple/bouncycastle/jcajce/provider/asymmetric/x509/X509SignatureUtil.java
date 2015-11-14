package org.ripple.bouncycastle.jcajce.provider.asymmetric.x509;

import java.io.ioexception;
import java.security.algorithmparameters;
import java.security.generalsecurityexception;
import java.security.invalidkeyexception;
import java.security.nosuchalgorithmexception;
import java.security.signature;
import java.security.signatureexception;
import java.security.spec.pssparameterspec;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1null;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dernull;
import org.ripple.bouncycastle.asn1.derobjectidentifier;
import org.ripple.bouncycastle.asn1.cryptopro.cryptoproobjectidentifiers;
import org.ripple.bouncycastle.asn1.nist.nistobjectidentifiers;
import org.ripple.bouncycastle.asn1.oiw.oiwobjectidentifiers;
import org.ripple.bouncycastle.asn1.pkcs.pkcsobjectidentifiers;
import org.ripple.bouncycastle.asn1.pkcs.rsassapssparams;
import org.ripple.bouncycastle.asn1.teletrust.teletrustobjectidentifiers;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;
import org.ripple.bouncycastle.asn1.x9.x9objectidentifiers;

class x509signatureutil
{
    private static final asn1null       dernull = dernull.instance;
    
    static void setsignatureparameters(
        signature signature,
        asn1encodable params)
        throws nosuchalgorithmexception, signatureexception, invalidkeyexception
    {
        if (params != null && !dernull.equals(params))
        {
            algorithmparameters  sigparams = algorithmparameters.getinstance(signature.getalgorithm(), signature.getprovider());
            
            try
            {
                sigparams.init(params.toasn1primitive().getencoded());
            }
            catch (ioexception e)
            {
                throw new signatureexception("ioexception decoding parameters: " + e.getmessage());
            }
            
            if (signature.getalgorithm().endswith("mgf1"))
            {
                try
                {
                    signature.setparameter(sigparams.getparameterspec(pssparameterspec.class));
                }
                catch (generalsecurityexception e)
                {
                    throw new signatureexception("exception extracting parameters: " + e.getmessage());
                }
            }
        }
    }
    
    static string getsignaturename(
        algorithmidentifier sigalgid) 
    {
        asn1encodable params = sigalgid.getparameters();
        
        if (params != null && !dernull.equals(params))
        {
            if (sigalgid.getalgorithm().equals(pkcsobjectidentifiers.id_rsassa_pss))
            {
                rsassapssparams rsaparams = rsassapssparams.getinstance(params);
                
                return getdigestalgname(rsaparams.gethashalgorithm().getalgorithm()) + "withrsaandmgf1";
            }
            if (sigalgid.getalgorithm().equals(x9objectidentifiers.ecdsa_with_sha2))
            {
                asn1sequence ecdsaparams = asn1sequence.getinstance(params);
                
                return getdigestalgname((derobjectidentifier)ecdsaparams.getobjectat(0)) + "withecdsa";
            }
        }

        return sigalgid.getalgorithm().getid();
    }
    
    /**
     * return the digest algorithm using one of the standard jca string
     * representations rather the the algorithm identifier (if possible).
     */
    private static string getdigestalgname(
        derobjectidentifier digestalgoid)
    {
        if (pkcsobjectidentifiers.md5.equals(digestalgoid))
        {
            return "md5";
        }
        else if (oiwobjectidentifiers.idsha1.equals(digestalgoid))
        {
            return "sha1";
        }
        else if (nistobjectidentifiers.id_sha224.equals(digestalgoid))
        {
            return "sha224";
        }
        else if (nistobjectidentifiers.id_sha256.equals(digestalgoid))
        {
            return "sha256";
        }
        else if (nistobjectidentifiers.id_sha384.equals(digestalgoid))
        {
            return "sha384";
        }
        else if (nistobjectidentifiers.id_sha512.equals(digestalgoid))
        {
            return "sha512";
        }
        else if (teletrustobjectidentifiers.ripemd128.equals(digestalgoid))
        {
            return "ripemd128";
        }
        else if (teletrustobjectidentifiers.ripemd160.equals(digestalgoid))
        {
            return "ripemd160";
        }
        else if (teletrustobjectidentifiers.ripemd256.equals(digestalgoid))
        {
            return "ripemd256";
        }
        else if (cryptoproobjectidentifiers.gostr3411.equals(digestalgoid))
        {
            return "gost3411";
        }
        else
        {
            return digestalgoid.getid();            
        }
    }
}
