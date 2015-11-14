package org.ripple.bouncycastle.asn1.x9;

import java.math.biginteger;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;

/**
 * asn.1 def for elliptic-curve field id structure. see
 * x9.62, for further details.
 */
public class x9fieldid
    extends asn1object
    implements x9objectidentifiers
{
    private asn1objectidentifier     id;
    private asn1primitive parameters;

    /**
     * constructor for elliptic curves over prime fields
     * <code>f<sub>2</sub></code>.
     * @param primep the prime <code>p</code> defining the prime field.
     */
    public x9fieldid(biginteger primep)
    {
        this.id = prime_field;
        this.parameters = new asn1integer(primep);
    }

    /**
     * constructor for elliptic curves over binary fields
     * <code>f<sub>2<sup>m</sup></sub></code>.
     * @param m  the exponent <code>m</code> of
     * <code>f<sub>2<sup>m</sup></sub></code>.
     * @param k1 the integer <code>k1</code> where <code>x<sup>m</sup> +
     * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
     * represents the reduction polynomial <code>f(z)</code>.
     * @param k2 the integer <code>k2</code> where <code>x<sup>m</sup> +
     * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
     * represents the reduction polynomial <code>f(z)</code>.
     * @param k3 the integer <code>k3</code> where <code>x<sup>m</sup> +
     * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
     * represents the reduction polynomial <code>f(z)</code>..
     */
    public x9fieldid(int m, int k1, int k2, int k3)
    {
        this.id = characteristic_two_field;
        asn1encodablevector fieldidparams = new asn1encodablevector();
        fieldidparams.add(new asn1integer(m));
        
        if (k2 == 0) 
        {
            fieldidparams.add(tpbasis);
            fieldidparams.add(new asn1integer(k1));
        } 
        else 
        {
            fieldidparams.add(ppbasis);
            asn1encodablevector pentanomialparams = new asn1encodablevector();
            pentanomialparams.add(new asn1integer(k1));
            pentanomialparams.add(new asn1integer(k2));
            pentanomialparams.add(new asn1integer(k3));
            fieldidparams.add(new dersequence(pentanomialparams));
        }
        
        this.parameters = new dersequence(fieldidparams);
    }

    public x9fieldid(
        asn1sequence  seq)
    {
        this.id = (asn1objectidentifier)seq.getobjectat(0);
        this.parameters = (asn1primitive)seq.getobjectat(1);
    }

    public asn1objectidentifier getidentifier()
    {
        return id;
    }

    public asn1primitive getparameters()
    {
        return parameters;
    }

    /**
     * produce a der encoding of the following structure.
     * <pre>
     *  fieldid ::= sequence {
     *      fieldtype       field-id.&amp;id({ioset}),
     *      parameters      field-id.&amp;type({ioset}{&#64;fieldtype})
     *  }
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        v.add(this.id);
        v.add(this.parameters);

        return new dersequence(v);
    }
}
