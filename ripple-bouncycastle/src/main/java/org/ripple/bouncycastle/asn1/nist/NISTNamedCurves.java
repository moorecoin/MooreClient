package org.ripple.bouncycastle.asn1.nist;

import java.util.enumeration;
import java.util.hashtable;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.sec.secnamedcurves;
import org.ripple.bouncycastle.asn1.sec.secobjectidentifiers;
import org.ripple.bouncycastle.asn1.x9.x9ecparameters;
import org.ripple.bouncycastle.util.strings;

/**
 * utility class for fetching curves using their nist names as published in fips-pub 186-3
 */
public class nistnamedcurves
{
    static final hashtable objids = new hashtable();
    static final hashtable names = new hashtable();

    static void definecurve(string name, asn1objectidentifier oid)
    {
        objids.put(name, oid);
        names.put(oid, name);
    }

    static
    {
        definecurve("b-571", secobjectidentifiers.sect571r1);
        definecurve("b-409", secobjectidentifiers.sect409r1);
        definecurve("b-283", secobjectidentifiers.sect283r1);
        definecurve("b-233", secobjectidentifiers.sect233r1);
        definecurve("b-163", secobjectidentifiers.sect163r2);
        definecurve("k-571", secobjectidentifiers.sect571k1);
        definecurve("k-409", secobjectidentifiers.sect409k1);
        definecurve("k-283", secobjectidentifiers.sect283k1);
        definecurve("k-233", secobjectidentifiers.sect233k1);
        definecurve("k-163", secobjectidentifiers.sect163k1);
        definecurve("p-521", secobjectidentifiers.secp521r1);
        definecurve("p-384", secobjectidentifiers.secp384r1);
        definecurve("p-256", secobjectidentifiers.secp256r1);
        definecurve("p-224", secobjectidentifiers.secp224r1);
        definecurve("p-192", secobjectidentifiers.secp192r1);
    }

    public static x9ecparameters getbyname(
        string  name)
    {
        asn1objectidentifier oid = (asn1objectidentifier)objids.get(strings.touppercase(name));

        if (oid != null)
        {
            return getbyoid(oid);
        }

        return null;
    }

    /**
     * return the x9ecparameters object for the named curve represented by
     * the passed in object identifier. null if the curve isn't present.
     *
     * @param oid an object identifier representing a named curve, if present.
     */
    public static x9ecparameters getbyoid(
        asn1objectidentifier  oid)
    {
        return secnamedcurves.getbyoid(oid);
    }

    /**
     * return the object identifier signified by the passed in name. null
     * if there is no object identifier associated with name.
     *
     * @return the object identifier associated with name, if present.
     */
    public static asn1objectidentifier getoid(
        string  name)
    {
        return (asn1objectidentifier)objids.get(strings.touppercase(name));
    }

    /**
     * return the named curve name represented by the given object identifier.
     */
    public static string getname(
        asn1objectidentifier  oid)
    {
        return (string)names.get(oid);
    }

    /**
     * returns an enumeration containing the name strings for curves
     * contained in this structure.
     */
    public static enumeration getnames()
    {
        return objids.keys();
    }
}
