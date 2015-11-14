package org.ripple.bouncycastle.jce;

import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.cryptopro.ecgost3410namedcurves;
import org.ripple.bouncycastle.crypto.params.ecdomainparameters;
import org.ripple.bouncycastle.jce.spec.ecnamedcurveparameterspec;

/**
 * a table of locally supported named curves.
 */
public class ecgost3410namedcurvetable
{
    /**
     * return a parameter spec representing the passed in named
     * curve. the routine returns null if the curve is not present.
     * 
     * @param name the name of the curve requested
     * @return a parameter spec for the curve, null if it is not available.
     */
    public static ecnamedcurveparameterspec getparameterspec(
        string  name)
    {
        ecdomainparameters  ecp = ecgost3410namedcurves.getbyname(name);
        if (ecp == null)
        {
            try
            {
                ecp = ecgost3410namedcurves.getbyoid(new asn1objectidentifier(name));
            }
            catch (illegalargumentexception e)
            {
                return null; // not an oid.
            }
        }
        
        if (ecp == null)
        {
            return null;
        }

        return new ecnamedcurveparameterspec(
                                        name,
                                        ecp.getcurve(),
                                        ecp.getg(),
                                        ecp.getn(),
                                        ecp.geth(),
                                        ecp.getseed());
    }

    /**
     * return an enumeration of the names of the available curves.
     *
     * @return an enumeration of the names of the available curves.
     */
    public static enumeration getnames()
    {
        return ecgost3410namedcurves.getnames();
    }
}
