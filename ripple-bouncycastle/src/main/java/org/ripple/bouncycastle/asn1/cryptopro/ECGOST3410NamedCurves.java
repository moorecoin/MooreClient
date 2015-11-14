package org.ripple.bouncycastle.asn1.cryptopro;

import java.math.biginteger;
import java.util.enumeration;
import java.util.hashtable;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.crypto.params.ecdomainparameters;
import org.ripple.bouncycastle.math.ec.eccurve;
import org.ripple.bouncycastle.math.ec.ecfieldelement;
import org.ripple.bouncycastle.math.ec.ecpoint;

/**
 * table of the available named parameters for gost 3410-2001.
 */
public class ecgost3410namedcurves
{
    static final hashtable objids = new hashtable();
    static final hashtable params = new hashtable();
    static final hashtable names = new hashtable();

    static
    {
        biginteger mod_p = new biginteger("115792089237316195423570985008687907853269984665640564039457584007913129639319");
        biginteger mod_q = new biginteger("115792089237316195423570985008687907853073762908499243225378155805079068850323");
        
        eccurve.fp curve = new eccurve.fp(
            mod_p, // p
            new biginteger("115792089237316195423570985008687907853269984665640564039457584007913129639316"), // a
            new biginteger("166")); // b

        ecdomainparameters ecparams = new ecdomainparameters(
            curve,
            new ecpoint.fp(curve,
                    new ecfieldelement.fp(curve.getq(),new biginteger("1")), // x
                    new ecfieldelement.fp(curve.getq(),new biginteger("64033881142927202683649881450433473985931760268884941288852745803908878638612"))), // y
            mod_q);
        
        params.put(cryptoproobjectidentifiers.gostr3410_2001_cryptopro_a, ecparams);  
        
        mod_p = new biginteger("115792089237316195423570985008687907853269984665640564039457584007913129639319");
        mod_q = new biginteger("115792089237316195423570985008687907853073762908499243225378155805079068850323");
        
        curve = new eccurve.fp(
                mod_p, // p
                new biginteger("115792089237316195423570985008687907853269984665640564039457584007913129639316"),
                new biginteger("166"));

        ecparams = new ecdomainparameters(
                curve,
                new ecpoint.fp(curve,
                        new ecfieldelement.fp(curve.getq(),new biginteger("1")), // x
                        new ecfieldelement.fp(curve.getq(),new biginteger("64033881142927202683649881450433473985931760268884941288852745803908878638612"))), // y
                mod_q);

        params.put(cryptoproobjectidentifiers.gostr3410_2001_cryptopro_xcha, ecparams); 
        
        mod_p = new biginteger("57896044618658097711785492504343953926634992332820282019728792003956564823193"); //p
        mod_q = new biginteger("57896044618658097711785492504343953927102133160255826820068844496087732066703"); //q
        
        curve = new eccurve.fp(
            mod_p, // p
            new biginteger("57896044618658097711785492504343953926634992332820282019728792003956564823190"), // a
            new biginteger("28091019353058090096996979000309560759124368558014865957655842872397301267595")); // b

        ecparams = new ecdomainparameters(
            curve,
            new ecpoint.fp(curve,
                           new ecfieldelement.fp(mod_p,new biginteger("1")), // x
                           new ecfieldelement.fp(mod_p,new biginteger("28792665814854611296992347458380284135028636778229113005756334730996303888124"))), // y
            mod_q); // q

        params.put(cryptoproobjectidentifiers.gostr3410_2001_cryptopro_b, ecparams);  
        
        mod_p = new biginteger("70390085352083305199547718019018437841079516630045180471284346843705633502619");
        mod_q = new biginteger("70390085352083305199547718019018437840920882647164081035322601458352298396601");
        
        curve = new eccurve.fp(
                mod_p, // p
                new biginteger("70390085352083305199547718019018437841079516630045180471284346843705633502616"),
                new biginteger("32858"));

        ecparams = new ecdomainparameters(
                curve,
                new ecpoint.fp(curve,
                               new ecfieldelement.fp(mod_p,new biginteger("0")),
                               new ecfieldelement.fp(mod_p,new biginteger("29818893917731240733471273240314769927240550812383695689146495261604565990247"))),
            mod_q);
        
        params.put(cryptoproobjectidentifiers.gostr3410_2001_cryptopro_xchb, ecparams);  
                                
        mod_p = new biginteger("70390085352083305199547718019018437841079516630045180471284346843705633502619"); //p
        mod_q = new biginteger("70390085352083305199547718019018437840920882647164081035322601458352298396601"); //q
        curve = new eccurve.fp(
            mod_p, // p
            new biginteger("70390085352083305199547718019018437841079516630045180471284346843705633502616"), // a
            new biginteger("32858")); // b

        ecparams = new ecdomainparameters(
            curve,
            new ecpoint.fp(curve,
                           new ecfieldelement.fp(mod_p,new biginteger("0")), // x
                           new ecfieldelement.fp(mod_p,new biginteger("29818893917731240733471273240314769927240550812383695689146495261604565990247"))), // y
            mod_q); // q

        params.put(cryptoproobjectidentifiers.gostr3410_2001_cryptopro_c, ecparams); 
            
        objids.put("gostr3410-2001-cryptopro-a", cryptoproobjectidentifiers.gostr3410_2001_cryptopro_a);
        objids.put("gostr3410-2001-cryptopro-b", cryptoproobjectidentifiers.gostr3410_2001_cryptopro_b);
        objids.put("gostr3410-2001-cryptopro-c", cryptoproobjectidentifiers.gostr3410_2001_cryptopro_c);
        objids.put("gostr3410-2001-cryptopro-xcha", cryptoproobjectidentifiers.gostr3410_2001_cryptopro_xcha);
        objids.put("gostr3410-2001-cryptopro-xchb", cryptoproobjectidentifiers.gostr3410_2001_cryptopro_xchb);
        
        names.put(cryptoproobjectidentifiers.gostr3410_2001_cryptopro_a, "gostr3410-2001-cryptopro-a");
        names.put(cryptoproobjectidentifiers.gostr3410_2001_cryptopro_b, "gostr3410-2001-cryptopro-b");
        names.put(cryptoproobjectidentifiers.gostr3410_2001_cryptopro_c, "gostr3410-2001-cryptopro-c");
        names.put(cryptoproobjectidentifiers.gostr3410_2001_cryptopro_xcha, "gostr3410-2001-cryptopro-xcha");
        names.put(cryptoproobjectidentifiers.gostr3410_2001_cryptopro_xchb, "gostr3410-2001-cryptopro-xchb");
    }

    /**
     * return the ecdomainparameters object for the given oid, null if it 
     * isn't present.
     *
     * @param oid an object identifier representing a named parameters, if present.
     */
    public static ecdomainparameters getbyoid(
        asn1objectidentifier  oid)
    {
        return (ecdomainparameters)params.get(oid);
    }

    /**
     * returns an enumeration containing the name strings for parameters
     * contained in this structure.
     */
    public static enumeration getnames()
    {
        return objids.keys();
    }

    public static ecdomainparameters getbyname(
        string  name)
    {
        asn1objectidentifier oid = (asn1objectidentifier)objids.get(name);

        if (oid != null)
        {
            return (ecdomainparameters)params.get(oid);
        }

        return null;
    }

    /**
     * return the named curve name represented by the given object identifier.
     */
    public static string getname(
        asn1objectidentifier  oid)
    {
        return (string)names.get(oid);
    }
    
    public static asn1objectidentifier getoid(string name)
    {
        return (asn1objectidentifier)objids.get(name);
    }
}
