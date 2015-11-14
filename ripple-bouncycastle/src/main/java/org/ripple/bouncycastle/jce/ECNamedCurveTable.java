package org.ripple.bouncycastle.jce;

import java.util.enumeration;
import java.util.vector;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.nist.nistnamedcurves;
import org.ripple.bouncycastle.asn1.sec.secnamedcurves;
import org.ripple.bouncycastle.asn1.teletrust.teletrustnamedcurves;
import org.ripple.bouncycastle.asn1.x9.x962namedcurves;
import org.ripple.bouncycastle.asn1.x9.x9ecparameters;
import org.ripple.bouncycastle.jce.spec.ecnamedcurveparameterspec;

/**
 * a table of locally supported named curves.
 */
public class ecnamedcurvetable
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
        x9ecparameters  ecp = x962namedcurves.getbyname(name);
        if (ecp == null)
        {
            try
            {
                ecp = x962namedcurves.getbyoid(new asn1objectidentifier(name));
            }
            catch (illegalargumentexception e)
            {
                // ignore - not an oid
            }
        }
        
        if (ecp == null)
        {
            ecp = secnamedcurves.getbyname(name);
            if (ecp == null)
            {
                try
                {
                    ecp = secnamedcurves.getbyoid(new asn1objectidentifier(name));
                }
                catch (illegalargumentexception e)
                {
                    // ignore - not an oid
                }
            }
        }

        if (ecp == null)
        {
            ecp = teletrustnamedcurves.getbyname(name);
            if (ecp == null)
            {
                try
                {
                    ecp = teletrustnamedcurves.getbyoid(new asn1objectidentifier(name));
                }
                catch (illegalargumentexception e)
                {
                    // ignore - not an oid
                }
            }
        }

        if (ecp == null)
        {
            ecp = nistnamedcurves.getbyname(name);
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
        vector v = new vector();
        
        addenumeration(v, x962namedcurves.getnames());
        addenumeration(v, secnamedcurves.getnames());
        addenumeration(v, nistnamedcurves.getnames());
        addenumeration(v, teletrustnamedcurves.getnames());

        return v.elements();
    }

    private static void addenumeration(
        vector v, 
        enumeration e)
    {
        while (e.hasmoreelements())
        {
            v.addelement(e.nextelement());
        }
    }
}
