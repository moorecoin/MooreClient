package org.ripple.bouncycastle.jce;

import java.io.unsupportedencodingexception;
import java.security.keyfactory;
import java.security.nosuchalgorithmexception;
import java.security.nosuchproviderexception;
import java.security.privatekey;
import java.security.provider;
import java.security.publickey;
import java.security.security;
import java.security.spec.pkcs8encodedkeyspec;
import java.security.spec.x509encodedkeyspec;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.cryptopro.cryptoproobjectidentifiers;
import org.ripple.bouncycastle.asn1.pkcs.privatekeyinfo;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;
import org.ripple.bouncycastle.asn1.x509.subjectpublickeyinfo;
import org.ripple.bouncycastle.asn1.x9.x962parameters;
import org.ripple.bouncycastle.asn1.x9.x9ecparameters;
import org.ripple.bouncycastle.asn1.x9.x9objectidentifiers;
import org.ripple.bouncycastle.jcajce.provider.asymmetric.util.ecutil;
import org.ripple.bouncycastle.jce.provider.bouncycastleprovider;

/**
 * utility class to allow conversion of ec key parameters to explicit from named
 * curves and back (where possible).
 */
public class eckeyutil
{
    /**
     * convert a passed in public ec key to have explicit parameters. if the key
     * is already using explicit parameters it is returned.
     *
     * @param key key to be converted
     * @param providername provider name to be used.
     * @return the equivalent key with explicit curve parameters
     * @throws illegalargumentexception
     * @throws nosuchalgorithmexception
     * @throws nosuchproviderexception
     */
    public static publickey publictoexplicitparameters(publickey key, string providername)
        throws illegalargumentexception, nosuchalgorithmexception, nosuchproviderexception
    {
        provider provider = security.getprovider(providername);

        if (provider == null)
        {
            throw new nosuchproviderexception("cannot find provider: " + providername);
        }

        return publictoexplicitparameters(key, provider);
    }

    /**
     * convert a passed in public ec key to have explicit parameters. if the key
     * is already using explicit parameters it is returned.
     *
     * @param key key to be converted
     * @param provider provider to be used.
     * @return the equivalent key with explicit curve parameters
     * @throws illegalargumentexception
     * @throws nosuchalgorithmexception
     */
    public static publickey publictoexplicitparameters(publickey key, provider provider)
        throws illegalargumentexception, nosuchalgorithmexception
    {
        try
        {
            subjectpublickeyinfo info = subjectpublickeyinfo.getinstance(asn1primitive.frombytearray(key.getencoded()));

            if (info.getalgorithmid().getobjectid().equals(cryptoproobjectidentifiers.gostr3410_2001))
            {
                throw new illegalargumentexception("cannot convert gost key to explicit parameters.");
            }
            else
            {
                x962parameters params = x962parameters.getinstance(info.getalgorithmid().getparameters());
                x9ecparameters curveparams;

                if (params.isnamedcurve())
                {
                    asn1objectidentifier oid = asn1objectidentifier.getinstance(params.getparameters());

                    curveparams = ecutil.getnamedcurvebyoid(oid);
                    // ignore seed value due to jdk bug
                    curveparams = new x9ecparameters(curveparams.getcurve(), curveparams.getg(), curveparams.getn(), curveparams.geth());
                }
                else if (params.isimplicitlyca())
                {
                    curveparams = new x9ecparameters(bouncycastleprovider.configuration.getecimplicitlyca().getcurve(), bouncycastleprovider.configuration.getecimplicitlyca().getg(), bouncycastleprovider.configuration.getecimplicitlyca().getn(), bouncycastleprovider.configuration.getecimplicitlyca().geth());
                }
                else
                {
                    return key;   // already explicit
                }

                params = new x962parameters(curveparams);

                info = new subjectpublickeyinfo(new algorithmidentifier(x9objectidentifiers.id_ecpublickey, params), info.getpublickeydata().getbytes());

                keyfactory keyfact = keyfactory.getinstance(key.getalgorithm(), provider);

                return keyfact.generatepublic(new x509encodedkeyspec(info.getencoded()));
            }
        }
        catch (illegalargumentexception e)
        {
            throw e;
        }
        catch (nosuchalgorithmexception e)
        {
            throw e;
        }
        catch (exception e)
        {               // shouldn't really happen...
            throw new unexpectedexception(e);
        }
    }

    /**
     * convert a passed in private ec key to have explicit parameters. if the key
     * is already using explicit parameters it is returned.
     *
     * @param key key to be converted
     * @param providername provider name to be used.
     * @return the equivalent key with explicit curve parameters
     * @throws illegalargumentexception
     * @throws nosuchalgorithmexception
     * @throws nosuchproviderexception
     */
    public static privatekey privatetoexplicitparameters(privatekey key, string providername)
        throws illegalargumentexception, nosuchalgorithmexception, nosuchproviderexception
    {
        provider provider = security.getprovider(providername);

        if (provider == null)
        {
            throw new nosuchproviderexception("cannot find provider: " + providername);
        }

        return privatetoexplicitparameters(key, provider);
    }

    /**
     * convert a passed in private ec key to have explicit parameters. if the key
     * is already using explicit parameters it is returned.
     *
     * @param key key to be converted
     * @param provider provider to be used.
     * @return the equivalent key with explicit curve parameters
     * @throws illegalargumentexception
     * @throws nosuchalgorithmexception
     */
    public static privatekey privatetoexplicitparameters(privatekey key, provider provider)
        throws illegalargumentexception, nosuchalgorithmexception
    {
        try
        {
            privatekeyinfo info = privatekeyinfo.getinstance(asn1primitive.frombytearray(key.getencoded()));

            if (info.getalgorithmid().getobjectid().equals(cryptoproobjectidentifiers.gostr3410_2001))
            {
                throw new unsupportedencodingexception("cannot convert gost key to explicit parameters.");
            }
            else
            {
                x962parameters params = x962parameters.getinstance(info.getalgorithmid().getparameters());
                x9ecparameters curveparams;

                if (params.isnamedcurve())
                {
                    asn1objectidentifier oid = asn1objectidentifier.getinstance(params.getparameters());

                    curveparams = ecutil.getnamedcurvebyoid(oid);
                    // ignore seed value due to jdk bug
                    curveparams = new x9ecparameters(curveparams.getcurve(), curveparams.getg(), curveparams.getn(), curveparams.geth());
                }
                else if (params.isimplicitlyca())
                {
                    curveparams = new x9ecparameters(bouncycastleprovider.configuration.getecimplicitlyca().getcurve(), bouncycastleprovider.configuration.getecimplicitlyca().getg(), bouncycastleprovider.configuration.getecimplicitlyca().getn(), bouncycastleprovider.configuration.getecimplicitlyca().geth());
                }
                else
                {
                    return key;   // already explicit
                }

                params = new x962parameters(curveparams);

                info = new privatekeyinfo(new algorithmidentifier(x9objectidentifiers.id_ecpublickey, params), info.parseprivatekey());

                keyfactory keyfact = keyfactory.getinstance(key.getalgorithm(), provider);

                return keyfact.generateprivate(new pkcs8encodedkeyspec(info.getencoded()));
            }
        }
        catch (illegalargumentexception e)
        {
            throw e;
        }
        catch (nosuchalgorithmexception e)
        {
            throw e;
        }
        catch (exception e)
        {          // shouldn't really happen
            throw new unexpectedexception(e);
        }
    }

    private static class unexpectedexception
        extends runtimeexception
    {
        private throwable cause;

        unexpectedexception(throwable cause)
        {
            super(cause.tostring());

            this.cause = cause;
        }

        public throwable getcause()
        {
            return cause;
        }
    }
}
