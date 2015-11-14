package org.ripple.bouncycastle.jcajce.provider.asymmetric.util;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encoding;
import org.ripple.bouncycastle.asn1.pkcs.privatekeyinfo;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;
import org.ripple.bouncycastle.asn1.x509.subjectpublickeyinfo;

public class keyutil
{
    public static byte[] getencodedsubjectpublickeyinfo(algorithmidentifier algid, asn1encodable keydata)
    {
        try
        {
            return getencodedsubjectpublickeyinfo(new subjectpublickeyinfo(algid, keydata));
        }
        catch (exception e)
        {
            return null;
        }
    }

    public static byte[] getencodedsubjectpublickeyinfo(algorithmidentifier algid, byte[] keydata)
    {
        try
        {
            return getencodedsubjectpublickeyinfo(new subjectpublickeyinfo(algid, keydata));
        }
        catch (exception e)
        {
            return null;
        }
    }

    public static byte[] getencodedsubjectpublickeyinfo(subjectpublickeyinfo info)
    {
         try
         {
             return info.getencoded(asn1encoding.der);
         }
         catch (exception e)
         {
             return null;
         }
    }

    public static byte[] getencodedprivatekeyinfo(algorithmidentifier algid, asn1encodable privkey)
    {
         try
         {
             privatekeyinfo info = new privatekeyinfo(algid, privkey.toasn1primitive());

             return getencodedprivatekeyinfo(info);
         }
         catch (exception e)
         {
             return null;
         }
    }

    public static byte[] getencodedprivatekeyinfo(privatekeyinfo info)
    {
         try
         {
             return info.getencoded(asn1encoding.der);
         }
         catch (exception e)
         {
             return null;
         }
    }
}
