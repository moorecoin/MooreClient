package org.ripple.bouncycastle.pqc.jcajce.provider;

import java.io.ioexception;
import java.security.accesscontroller;
import java.security.privatekey;
import java.security.privilegedaction;
import java.security.provider;
import java.security.publickey;
import java.util.hashmap;
import java.util.map;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.pkcs.privatekeyinfo;
import org.ripple.bouncycastle.asn1.x509.subjectpublickeyinfo;
import org.ripple.bouncycastle.jcajce.provider.config.configurableprovider;
import org.ripple.bouncycastle.jcajce.provider.config.providerconfiguration;
import org.ripple.bouncycastle.jcajce.provider.util.algorithmprovider;
import org.ripple.bouncycastle.jcajce.provider.util.asymmetrickeyinfoconverter;

public class bouncycastlepqcprovider
    extends provider
    implements configurableprovider
{
    private static string info = "bouncycastle post-quantum security provider v1.48";

    public static string provider_name = "bcpqc";

    public static final providerconfiguration configuration = null;


    private static final map keyinfoconverters = new hashmap();

    /*
    * configurable symmetric ciphers
    */
    private static final string algorithm_package = "org.bouncycastle.pqc.jcajce.provider.";
    private static final string[] algorithms =
        {
            "rainbow", "mceliece"
        };

    /**
     * construct a new provider.  this should only be required when
     * using runtime registration of the provider using the
     * <code>security.addprovider()</code> mechanism.
     */
    public bouncycastlepqcprovider()
    {
        super(provider_name, 1.48, info);

        accesscontroller.doprivileged(new privilegedaction()
        {
            public object run()
            {
                setup();
                return null;
            }
        });
    }

    private void setup()
    {
        loadalgorithms(algorithm_package, algorithms);
    }

    private void loadalgorithms(string packagename, string[] names)
    {
        for (int i = 0; i != names.length; i++)
        {
            class clazz = null;
            try
            {
                classloader loader = this.getclass().getclassloader();

                if (loader != null)
                {
                    clazz = loader.loadclass(packagename + names[i] + "$mappings");
                }
                else
                {
                    clazz = class.forname(packagename + names[i] + "$mappings");
                }
            }
            catch (classnotfoundexception e)
            {
                // ignore
            }

            if (clazz != null)
            {
                try
                {
                    ((algorithmprovider)clazz.newinstance()).configure(this);
                }
                catch (exception e)
                {   // this should never ever happen!!
                    throw new internalerror("cannot create instance of "
                        + packagename + names[i] + "$mappings : " + e);
                }
            }
        }
    }

    public void setparameter(string parametername, object parameter)
    {
        synchronized (configuration)
        {
            //((bouncycastleproviderconfiguration)configuration).setparameter(parametername, parameter);
        }
    }

    public boolean hasalgorithm(string type, string name)
    {
        return containskey(type + "." + name) || containskey("alg.alias." + type + "." + name);
    }

    public void addalgorithm(string key, string value)
    {
        if (containskey(key))
        {
            throw new illegalstateexception("duplicate provider key (" + key + ") found");
        }

        put(key, value);
    }

    public void addkeyinfoconverter(asn1objectidentifier oid, asymmetrickeyinfoconverter keyinfoconverter)
    {
        keyinfoconverters.put(oid, keyinfoconverter);
    }

    public static publickey getpublickey(subjectpublickeyinfo publickeyinfo)
        throws ioexception
    {
        asymmetrickeyinfoconverter converter = (asymmetrickeyinfoconverter)keyinfoconverters.get(publickeyinfo.getalgorithm().getalgorithm());

        if (converter == null)
        {
            return null;
        }

        return converter.generatepublic(publickeyinfo);
    }

    public static privatekey getprivatekey(privatekeyinfo privatekeyinfo)
        throws ioexception
    {
        asymmetrickeyinfoconverter converter = (asymmetrickeyinfoconverter)keyinfoconverters.get(privatekeyinfo.getprivatekeyalgorithm().getalgorithm());

        if (converter == null)
        {
            return null;
        }

        return converter.generateprivate(privatekeyinfo);
    }
}
