package org.ripple.bouncycastle.asn1.x9;

import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;

/**
 * asn.1 def for diffie-hellman key exchange keyspecificinfo structure. see
 * rfc 2631, or x9.42, for further details.
 */
public class keyspecificinfo
    extends asn1object
{
    private asn1objectidentifier algorithm;
    private asn1octetstring      counter;

    public keyspecificinfo(
        asn1objectidentifier algorithm,
        asn1octetstring      counter)
    {
        this.algorithm = algorithm;
        this.counter = counter;
    }

    public keyspecificinfo(
        asn1sequence  seq)
    {
        enumeration e = seq.getobjects();

        algorithm = (asn1objectidentifier)e.nextelement();
        counter = (asn1octetstring)e.nextelement();
    }

    public asn1objectidentifier getalgorithm()
    {
        return algorithm;
    }

    public asn1octetstring getcounter()
    {
        return counter;
    }

    /**
     * produce an object suitable for an asn1outputstream.
     * <pre>
     *  keyspecificinfo ::= sequence {
     *      algorithm object identifier,
     *      counter octet string size (4..4)
     *  }
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector  v = new asn1encodablevector();

        v.add(algorithm);
        v.add(counter);

        return new dersequence(v);
    }
}
