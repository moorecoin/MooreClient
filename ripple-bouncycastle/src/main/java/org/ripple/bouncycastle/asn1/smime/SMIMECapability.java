package org.ripple.bouncycastle.asn1.smime;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.nist.nistobjectidentifiers;
import org.ripple.bouncycastle.asn1.pkcs.pkcsobjectidentifiers;

public class smimecapability
    extends asn1object
{
    /**
     * general preferences
     */
    public static final asn1objectidentifier prefersigneddata = pkcsobjectidentifiers.prefersigneddata;
    public static final asn1objectidentifier cannotdecryptany = pkcsobjectidentifiers.cannotdecryptany;
    public static final asn1objectidentifier smimecapabilitiesversions = pkcsobjectidentifiers.smimecapabilitiesversions;

    /**
     * encryption algorithms preferences
     */
    public static final asn1objectidentifier des_cbc = new asn1objectidentifier("1.3.14.3.2.7");
    public static final asn1objectidentifier des_ede3_cbc = pkcsobjectidentifiers.des_ede3_cbc;
    public static final asn1objectidentifier rc2_cbc = pkcsobjectidentifiers.rc2_cbc;
    public static final asn1objectidentifier aes128_cbc = nistobjectidentifiers.id_aes128_cbc;
    public static final asn1objectidentifier aes192_cbc = nistobjectidentifiers.id_aes192_cbc;
    public static final asn1objectidentifier aes256_cbc = nistobjectidentifiers.id_aes256_cbc;
    
    private asn1objectidentifier capabilityid;
    private asn1encodable        parameters;

    public smimecapability(
        asn1sequence seq)
    {
        capabilityid = (asn1objectidentifier)seq.getobjectat(0);

        if (seq.size() > 1)
        {
            parameters = (asn1primitive)seq.getobjectat(1);
        }
    }

    public smimecapability(
        asn1objectidentifier capabilityid,
        asn1encodable        parameters)
    {
        this.capabilityid = capabilityid;
        this.parameters = parameters;
    }
    
    public static smimecapability getinstance(
        object obj)
    {
        if (obj == null || obj instanceof smimecapability)
        {
            return (smimecapability)obj;
        }
        
        if (obj instanceof asn1sequence)
        {
            return new smimecapability((asn1sequence)obj);
        }
        
        throw new illegalargumentexception("invalid smimecapability");
    } 

    public asn1objectidentifier getcapabilityid()
    {
        return capabilityid;
    }

    public asn1encodable getparameters()
    {
        return parameters;
    }

    /**
     * produce an object suitable for an asn1outputstream.
     * <pre> 
     * smimecapability ::= sequence {
     *     capabilityid object identifier,
     *     parameters any defined by capabilityid optional 
     * }
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector  v = new asn1encodablevector();

        v.add(capabilityid);
        
        if (parameters != null)
        {
            v.add(parameters);
        }
        
        return new dersequence(v);
    }
}
