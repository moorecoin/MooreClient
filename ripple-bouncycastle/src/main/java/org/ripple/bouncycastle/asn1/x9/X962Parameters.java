package org.ripple.bouncycastle.asn1.x9;

import org.ripple.bouncycastle.asn1.asn1choice;
import org.ripple.bouncycastle.asn1.asn1null;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1taggedobject;

public class x962parameters
    extends asn1object
    implements asn1choice
{
    private asn1primitive           params = null;

    public static x962parameters getinstance(
        object obj)
    {
        if (obj == null || obj instanceof x962parameters) 
        {
            return (x962parameters)obj;
        }
        
        if (obj instanceof asn1primitive) 
        {
            return new x962parameters((asn1primitive)obj);
        }
        
        throw new illegalargumentexception("unknown object in getinstance()");
    }
    
    public static x962parameters getinstance(
        asn1taggedobject obj,
        boolean          explicit)
    {
        return getinstance(obj.getobject()); // must be explicitly tagged
    }
    
    public x962parameters(
        x9ecparameters      ecparameters)
    {
        this.params = ecparameters.toasn1primitive();
    }

    public x962parameters(
        asn1objectidentifier  namedcurve)
    {
        this.params = namedcurve;
    }

    public x962parameters(
        asn1primitive           obj)
    {
        this.params = obj;
    }

    public boolean isnamedcurve()
    {
        return (params instanceof asn1objectidentifier);
    }

    public boolean isimplicitlyca()
    {
        return (params instanceof asn1null);
    }

    public asn1primitive getparameters()
    {
        return params;
    }

    /**
     * produce an object suitable for an asn1outputstream.
     * <pre>
     * parameters ::= choice {
     *    ecparameters ecparameters,
     *    namedcurve   curves.&id({curvenames}),
     *    implicitlyca null
     * }
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        return (asn1primitive)params;
    }
}
