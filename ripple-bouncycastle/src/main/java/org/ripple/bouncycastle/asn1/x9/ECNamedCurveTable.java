package org.ripple.bouncycastle.asn1.x9;

import java.util.enumeration;
import java.util.vector;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.nist.nistnamedcurves;
import org.ripple.bouncycastle.asn1.sec.secnamedcurves;
import org.ripple.bouncycastle.asn1.teletrust.teletrustnamedcurves;

/**
 * a general class that reads all x9.62 style ec curve tables.
 */
public class ecnamedcurvetable
{
    /**
     * return a x9ecparameters object representing the passed in named
     * curve. the routine returns null if the curve is not present.
     *
     * @param name the name of the curve requested
     * @return an x9ecparameters object or null if the curve is not available.
     */
    public static x9ecparameters getbyname(
        string name)
    {
        x9ecparameters ecp = x962namedcurves.getbyname(name);

        if (ecp == null)
        {
            ecp = secnamedcurves.getbyname(name);
        }

        if (ecp == null)
        {
            ecp = teletrustnamedcurves.getbyname(name);
        }

        if (ecp == null)
        {
            ecp = nistnamedcurves.getbyname(name);
        }

        return ecp;
    }

    /**
     * return a x9ecparameters object representing the passed in named
     * curve.
     *
     * @param oid the object id of the curve requested
     * @return an x9ecparameters object or null if the curve is not available.
     */
    public static x9ecparameters getbyoid(
        asn1objectidentifier oid)
    {
        x9ecparameters ecp = x962namedcurves.getbyoid(oid);

        if (ecp == null)
        {
            ecp = secnamedcurves.getbyoid(oid);
        }

        if (ecp == null)
        {
            ecp = teletrustnamedcurves.getbyoid(oid);
        }

        return ecp;
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
