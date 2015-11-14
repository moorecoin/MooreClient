package org.ripple.bouncycastle.jcajce.provider.asymmetric.util;

import java.security.invalidkeyexception;
import java.security.privatekey;
import java.security.publickey;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.cryptopro.ecgost3410namedcurves;
import org.ripple.bouncycastle.asn1.nist.nistnamedcurves;
import org.ripple.bouncycastle.asn1.pkcs.privatekeyinfo;
import org.ripple.bouncycastle.asn1.sec.secnamedcurves;
import org.ripple.bouncycastle.asn1.teletrust.teletrustnamedcurves;
import org.ripple.bouncycastle.asn1.x509.subjectpublickeyinfo;
import org.ripple.bouncycastle.asn1.x9.x962namedcurves;
import org.ripple.bouncycastle.asn1.x9.x9ecparameters;
import org.ripple.bouncycastle.crypto.params.asymmetrickeyparameter;
import org.ripple.bouncycastle.crypto.params.ecdomainparameters;
import org.ripple.bouncycastle.crypto.params.ecprivatekeyparameters;
import org.ripple.bouncycastle.crypto.params.ecpublickeyparameters;
import org.ripple.bouncycastle.jcajce.provider.asymmetric.ec.bcecpublickey;
import org.ripple.bouncycastle.jce.interfaces.ecprivatekey;
import org.ripple.bouncycastle.jce.interfaces.ecpublickey;
import org.ripple.bouncycastle.jce.provider.bouncycastleprovider;
import org.ripple.bouncycastle.jce.spec.ecparameterspec;

/**
 * utility class for converting jce/jca ecdsa, ecdh, and ecdhc
 * objects into their org.bouncycastle.crypto counterparts.
 */
public class ecutil
{
    /**
     * returns a sorted array of middle terms of the reduction polynomial.
     * @param k the unsorted array of middle terms of the reduction polynomial
     * of length 1 or 3.
     * @return the sorted array of middle terms of the reduction polynomial.
     * this array always has length 3.
     */
    static int[] convertmidterms(
        int[] k)
    {
        int[] res = new int[3];
        
        if (k.length == 1)
        {
            res[0] = k[0];
        }
        else
        {
            if (k.length != 3)
            {
                throw new illegalargumentexception("only trinomials and pentanomials supported");
            }

            if (k[0] < k[1] && k[0] < k[2])
            {
                res[0] = k[0];
                if (k[1] < k[2])
                {
                    res[1] = k[1];
                    res[2] = k[2];
                }
                else
                {
                    res[1] = k[2];
                    res[2] = k[1];
                }
            }
            else if (k[1] < k[2])
            {
                res[0] = k[1];
                if (k[0] < k[2])
                {
                    res[1] = k[0];
                    res[2] = k[2];
                }
                else
                {
                    res[1] = k[2];
                    res[2] = k[0];
                }
            }
            else
            {
                res[0] = k[2];
                if (k[0] < k[1])
                {
                    res[1] = k[0];
                    res[2] = k[1];
                }
                else
                {
                    res[1] = k[1];
                    res[2] = k[0];
                }
            }
        }

        return res;
    }

    public static asymmetrickeyparameter generatepublickeyparameter(
        publickey    key)
        throws invalidkeyexception
    {
        if (key instanceof ecpublickey)
        {
            ecpublickey    k = (ecpublickey)key;
            ecparameterspec s = k.getparameters();

            if (s == null)
            {
                s = bouncycastleprovider.configuration.getecimplicitlyca();

                return new ecpublickeyparameters(
                            ((bcecpublickey)k).enginegetq(),
                            new ecdomainparameters(s.getcurve(), s.getg(), s.getn(), s.geth(), s.getseed()));
            }
            else
            {
                return new ecpublickeyparameters(
                            k.getq(),
                            new ecdomainparameters(s.getcurve(), s.getg(), s.getn(), s.geth(), s.getseed()));
            }
        }
        else if (key instanceof java.security.interfaces.ecpublickey)
        {
            java.security.interfaces.ecpublickey pubkey = (java.security.interfaces.ecpublickey)key;
            ecparameterspec s = ec5util.convertspec(pubkey.getparams(), false);
            return new ecpublickeyparameters(
                ec5util.convertpoint(pubkey.getparams(), pubkey.getw(), false),
                            new ecdomainparameters(s.getcurve(), s.getg(), s.getn(), s.geth(), s.getseed()));
        }
        else
        {
            // see if we can build a key from key.getencoded()
            try
            {
                byte[] bytes = key.getencoded();

                if (bytes == null)
                {
                    throw new invalidkeyexception("no encoding for ec public key");
                }

                publickey publickey = bouncycastleprovider.getpublickey(subjectpublickeyinfo.getinstance(bytes));

                if (publickey instanceof java.security.interfaces.ecpublickey)
                {
                    return ecutil.generatepublickeyparameter(publickey);
                }
            }
            catch (exception e)
            {
                throw new invalidkeyexception("cannot identify ec public key: " + e.tostring());
            }
        }

        throw new invalidkeyexception("cannot identify ec public key.");
    }

    public static asymmetrickeyparameter generateprivatekeyparameter(
        privatekey    key)
        throws invalidkeyexception
    {
        if (key instanceof ecprivatekey)
        {
            ecprivatekey  k = (ecprivatekey)key;
            ecparameterspec s = k.getparameters();

            if (s == null)
            {
                s = bouncycastleprovider.configuration.getecimplicitlyca();
            }

            return new ecprivatekeyparameters(
                            k.getd(),
                            new ecdomainparameters(s.getcurve(), s.getg(), s.getn(), s.geth(), s.getseed()));
        }
        else if (key instanceof java.security.interfaces.ecprivatekey)
        {
            java.security.interfaces.ecprivatekey privkey = (java.security.interfaces.ecprivatekey)key;
            ecparameterspec s = ec5util.convertspec(privkey.getparams(), false);
            return new ecprivatekeyparameters(
                            privkey.gets(),
                            new ecdomainparameters(s.getcurve(), s.getg(), s.getn(), s.geth(), s.getseed()));
        }
        else
        {
            // see if we can build a key from key.getencoded()
            try
            {
                byte[] bytes = key.getencoded();

                if (bytes == null)
                {
                    throw new invalidkeyexception("no encoding for ec private key");
                }

                privatekey privatekey = bouncycastleprovider.getprivatekey(privatekeyinfo.getinstance(bytes));

                if (privatekey instanceof java.security.interfaces.ecprivatekey)
                {
                    return ecutil.generateprivatekeyparameter(privatekey);
                }
            }
            catch (exception e)
            {
                throw new invalidkeyexception("cannot identify ec private key: " + e.tostring());
            }
        }

        throw new invalidkeyexception("can't identify ec private key.");
    }

    public static asn1objectidentifier getnamedcurveoid(
        string name)
    {
        asn1objectidentifier oid = x962namedcurves.getoid(name);
        
        if (oid == null)
        {
            oid = secnamedcurves.getoid(name);
            if (oid == null)
            {
                oid = nistnamedcurves.getoid(name);
            }
            if (oid == null)
            {
                oid = teletrustnamedcurves.getoid(name);
            }
            if (oid == null)
            {
                oid = ecgost3410namedcurves.getoid(name);
            }
        }

        return oid;
    }
    
    public static x9ecparameters getnamedcurvebyoid(
        asn1objectidentifier oid)
    {
        x9ecparameters params = x962namedcurves.getbyoid(oid);
        
        if (params == null)
        {
            params = secnamedcurves.getbyoid(oid);
            if (params == null)
            {
                params = nistnamedcurves.getbyoid(oid);
            }
            if (params == null)
            {
                params = teletrustnamedcurves.getbyoid(oid);
            }
        }

        return params;
    }

    public static string getcurvename(
        asn1objectidentifier oid)
    {
        string name = x962namedcurves.getname(oid);
        
        if (name == null)
        {
            name = secnamedcurves.getname(oid);
            if (name == null)
            {
                name = nistnamedcurves.getname(oid);
            }
            if (name == null)
            {
                name = teletrustnamedcurves.getname(oid);
            }
            if (name == null)
            {
                name = ecgost3410namedcurves.getname(oid);
            }
        }

        return name;
    }
}
