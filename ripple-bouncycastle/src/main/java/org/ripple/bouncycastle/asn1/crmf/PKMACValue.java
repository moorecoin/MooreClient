package org.ripple.bouncycastle.asn1.crmf;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.derbitstring;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.cmp.cmpobjectidentifiers;
import org.ripple.bouncycastle.asn1.cmp.pbmparameter;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;

/**
 * password-based mac value for use with poposigningkeyinput.
 */
public class pkmacvalue
    extends asn1object
{
    private algorithmidentifier  algid;
    private derbitstring        value;

    private pkmacvalue(asn1sequence seq)
    {
        algid = algorithmidentifier.getinstance(seq.getobjectat(0));
        value = derbitstring.getinstance(seq.getobjectat(1));
    }

    public static pkmacvalue getinstance(object o)
    {
        if (o instanceof pkmacvalue)
        {
            return (pkmacvalue)o;
        }

        if (o != null)
        {
            return new pkmacvalue(asn1sequence.getinstance(o));
        }

        return null;
    }

    public static pkmacvalue getinstance(asn1taggedobject obj, boolean isexplicit)
    {
        return getinstance(asn1sequence.getinstance(obj, isexplicit));
    }

    /**
     * creates a new pkmacvalue.
     * @param params parameters for password-based mac
     * @param value mac of the der-encoded subjectpublickeyinfo
     */
    public pkmacvalue(
        pbmparameter params,
        derbitstring value)
    {
        this(new algorithmidentifier(
                    cmpobjectidentifiers.passwordbasedmac, params), value);
    }

    /**
     * creates a new pkmacvalue.
     * @param aid cmpobjectidentifiers.passwordbasedmac, with pbmparameter
     * @param value mac of the der-encoded subjectpublickeyinfo
     */
    public pkmacvalue(
        algorithmidentifier aid,
        derbitstring value)
    {
        this.algid = aid;
        this.value = value;
    }

    public algorithmidentifier getalgid()
    {
        return algid;
    }

    public derbitstring getvalue()
    {
        return value;
    }

    /**
     * <pre>
     * pkmacvalue ::= sequence {
     *      algid  algorithmidentifier,
     *      -- algorithm value shall be passwordbasedmac 1.2.840.113533.7.66.13
     *      -- parameter value is pbmparameter
     *      value  bit string }
     * </pre>
     * @return a basic asn.1 object representation.
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        v.add(algid);
        v.add(value);

        return new dersequence(v);
    }
}
