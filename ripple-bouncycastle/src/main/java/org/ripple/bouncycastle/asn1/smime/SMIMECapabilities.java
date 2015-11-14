package org.ripple.bouncycastle.asn1.smime;

import java.util.enumeration;
import java.util.vector;

import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.cms.attribute;
import org.ripple.bouncycastle.asn1.pkcs.pkcsobjectidentifiers;

/**
 * handler class for dealing with s/mime capabilities
 */
public class smimecapabilities
    extends asn1object
{
    /**
     * general preferences
     */
    public static final asn1objectidentifier prefersigneddata = pkcsobjectidentifiers.prefersigneddata;
    public static final asn1objectidentifier cannotdecryptany = pkcsobjectidentifiers.cannotdecryptany;
    public static final asn1objectidentifier smimecapabilitesversions = pkcsobjectidentifiers.smimecapabilitiesversions;

    /**
     * encryption algorithms preferences
     */
    public static final asn1objectidentifier des_cbc = new asn1objectidentifier("1.3.14.3.2.7");
    public static final asn1objectidentifier des_ede3_cbc = pkcsobjectidentifiers.des_ede3_cbc;
    public static final asn1objectidentifier rc2_cbc = pkcsobjectidentifiers.rc2_cbc;
    
    private asn1sequence         capabilities;

    /**
     * return an attribute object from the given object.
     *
     * @param o the object we want converted.
     * @exception illegalargumentexception if the object cannot be converted.
     */
    public static smimecapabilities getinstance(
        object o)
    {
        if (o == null || o instanceof smimecapabilities)
        {
            return (smimecapabilities)o;
        }
        
        if (o instanceof asn1sequence)
        {
            return new smimecapabilities((asn1sequence)o);
        }

        if (o instanceof attribute)
        {
            return new smimecapabilities(
                (asn1sequence)(((attribute)o).getattrvalues().getobjectat(0)));
        }

        throw new illegalargumentexception("unknown object in factory: " + o.getclass().getname());
    }
    
    public smimecapabilities(
        asn1sequence seq)
    {
        capabilities = seq;
    }

    /**
     * returns a vector with 0 or more objects of all the capabilities
     * matching the passed in capability oid. if the oid passed is null the
     * entire set is returned.
     */
    public vector getcapabilities(
        asn1objectidentifier capability)
    {
        enumeration e = capabilities.getobjects();
        vector      list = new vector();

        if (capability == null)
        {
            while (e.hasmoreelements())
            {
                smimecapability  cap = smimecapability.getinstance(e.nextelement());

                list.addelement(cap);
            }
        }
        else
        {
            while (e.hasmoreelements())
            {
                smimecapability  cap = smimecapability.getinstance(e.nextelement());

                if (capability.equals(cap.getcapabilityid()))
                {
                    list.addelement(cap);
                }
            }
        }

        return list;
    }

    /** 
     * produce an object suitable for an asn1outputstream.
     * <pre>
     * smimecapabilities ::= sequence of smimecapability
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        return capabilities;
    }
}
