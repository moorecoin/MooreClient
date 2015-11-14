package org.ripple.bouncycastle.asn1.x9;

import java.math.biginteger;

import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.deroctetstring;
import org.ripple.bouncycastle.math.ec.ecfieldelement;

/**
 * class for processing an fieldelement as a der object.
 */
public class x9fieldelement
    extends asn1object
{
    protected ecfieldelement  f;
    
    private static x9integerconverter converter = new x9integerconverter();

    public x9fieldelement(ecfieldelement f)
    {
        this.f = f;
    }
    
    public x9fieldelement(biginteger p, asn1octetstring s)
    {
        this(new ecfieldelement.fp(p, new biginteger(1, s.getoctets())));
    }
    
    public x9fieldelement(int m, int k1, int k2, int k3, asn1octetstring s)
    {
        this(new ecfieldelement.f2m(m, k1, k2, k3, new biginteger(1, s.getoctets())));
    }
    
    public ecfieldelement getvalue()
    {
        return f;
    }
    
    /**
     * produce an object suitable for an asn1outputstream.
     * <pre>
     *  fieldelement ::= octet string
     * </pre>
     * <p>
     * <ol>
     * <li> if <i>q</i> is an odd prime then the field element is
     * processed as an integer and converted to an octet string
     * according to x 9.62 4.3.1.</li>
     * <li> if <i>q</i> is 2<sup>m</sup> then the bit string
     * contained in the field element is converted into an octet
     * string with the same ordering padded at the front if necessary.
     * </li>
     * </ol>
     */
    public asn1primitive toasn1primitive()
    {
        int bytecount = converter.getbytelength(f);
        byte[] paddedbiginteger = converter.integertobytes(f.tobiginteger(), bytecount);

        return new deroctetstring(paddedbiginteger);
    }
}
