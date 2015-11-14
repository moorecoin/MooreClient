package org.ripple.bouncycastle.asn1.cmp;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;

/**
 * example infotypeandvalue contents include, but are not limited
 * to, the following (un-comment in this asn.1 module and use as
 * appropriate for a given environment):
 * <pre>
 *   id-it-caprotenccert    object identifier ::= {id-it 1}
 *      caprotenccertvalue      ::= cmpcertificate
 *   id-it-signkeypairtypes object identifier ::= {id-it 2}
 *     signkeypairtypesvalue   ::= sequence of algorithmidentifier
 *   id-it-enckeypairtypes  object identifier ::= {id-it 3}
 *     enckeypairtypesvalue    ::= sequence of algorithmidentifier
 *   id-it-preferredsymmalg object identifier ::= {id-it 4}
 *      preferredsymmalgvalue   ::= algorithmidentifier
 *   id-it-cakeyupdateinfo  object identifier ::= {id-it 5}
 *      cakeyupdateinfovalue    ::= cakeyupdanncontent
 *   id-it-currentcrl       object identifier ::= {id-it 6}
 *      currentcrlvalue         ::= certificatelist
 *   id-it-unsupportedoids  object identifier ::= {id-it 7}
 *      unsupportedoidsvalue    ::= sequence of object identifier
 *   id-it-keypairparamreq  object identifier ::= {id-it 10}
 *      keypairparamreqvalue    ::= object identifier
 *   id-it-keypairparamrep  object identifier ::= {id-it 11}
 *      keypairparamrepvalue    ::= algorithmidentifer
 *   id-it-revpassphrase    object identifier ::= {id-it 12}
 *      revpassphrasevalue      ::= encryptedvalue
 *   id-it-implicitconfirm  object identifier ::= {id-it 13}
 *      implicitconfirmvalue    ::= null
 *   id-it-confirmwaittime  object identifier ::= {id-it 14}
 *      confirmwaittimevalue    ::= generalizedtime
 *   id-it-origpkimessage   object identifier ::= {id-it 15}
 *      origpkimessagevalue     ::= pkimessages
 *   id-it-supplangtags     object identifier ::= {id-it 16}
 *      supplangtagsvalue       ::= sequence of utf8string
 *
 * where
 *
 *   id-pkix object identifier ::= {
 *      iso(1) identified-organization(3)
 *      dod(6) internet(1) security(5) mechanisms(5) pkix(7)}
 * and
 *      id-it   object identifier ::= {id-pkix 4}
 * </pre>
 */
public class infotypeandvalue
    extends asn1object
{
    private asn1objectidentifier infotype;
    private asn1encodable       infovalue;

    private infotypeandvalue(asn1sequence seq)
    {
        infotype = asn1objectidentifier.getinstance(seq.getobjectat(0));

        if (seq.size() > 1)
        {
            infovalue = (asn1encodable)seq.getobjectat(1);
        }
    }

    public static infotypeandvalue getinstance(object o)
    {
        if (o instanceof infotypeandvalue)
        {
            return (infotypeandvalue)o;
        }

        if (o != null)
        {
            return new infotypeandvalue(asn1sequence.getinstance(o));
        }

        return null;
    }

    public infotypeandvalue(
        asn1objectidentifier infotype)
    {
        this.infotype = infotype;
        this.infovalue = null;
    }

    public infotypeandvalue(
        asn1objectidentifier infotype,
        asn1encodable optionalvalue)
    {
        this.infotype = infotype;
        this.infovalue = optionalvalue;
    }

    public asn1objectidentifier getinfotype()
    {
        return infotype;
    }

    public asn1encodable getinfovalue()
    {
        return infovalue;
    }

    /**
     * <pre>
     * infotypeandvalue ::= sequence {
     *                         infotype               object identifier,
     *                         infovalue              any defined by infotype  optional
     * }
     * </pre>
     * @return a basic asn.1 object representation.
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        v.add(infotype);

        if (infovalue != null)
        {
            v.add(infovalue);
        }

        return new dersequence(v);
    }
}
