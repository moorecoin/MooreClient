package org.ripple.bouncycastle.asn1.smime;

import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.derset;
import org.ripple.bouncycastle.asn1.dertaggedobject;
import org.ripple.bouncycastle.asn1.cms.attribute;
import org.ripple.bouncycastle.asn1.cms.issuerandserialnumber;
import org.ripple.bouncycastle.asn1.cms.recipientkeyidentifier;

/**
 * the smimeencryptionkeypreference object.
 * <pre>
 * smimeencryptionkeypreference ::= choice {
 *     issuerandserialnumber   [0] issuerandserialnumber,
 *     receipentkeyid          [1] recipientkeyidentifier,
 *     subjectaltkeyidentifier [2] subjectkeyidentifier
 * }
 * </pre>
 */
public class smimeencryptionkeypreferenceattribute
    extends attribute
{
    public smimeencryptionkeypreferenceattribute(
        issuerandserialnumber issandser)
    {
        super(smimeattributes.encrypkeypref,
                new derset(new dertaggedobject(false, 0, issandser)));
    }
    
    public smimeencryptionkeypreferenceattribute(
        recipientkeyidentifier rkeyid)
    {

        super(smimeattributes.encrypkeypref, 
                    new derset(new dertaggedobject(false, 1, rkeyid)));
    }
    
    /**
     * @param skeyid the subjectkeyidentifier value (normally the x.509 one)
     */
    public smimeencryptionkeypreferenceattribute(
        asn1octetstring skeyid)
    {

        super(smimeattributes.encrypkeypref,
                    new derset(new dertaggedobject(false, 2, skeyid)));
    }
}
