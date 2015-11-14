package org.ripple.bouncycastle.asn1.x509;

import org.ripple.bouncycastle.asn1.asn1boolean;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;

/**
 * <pre>
 * issuingdistributionpoint ::= sequence { 
 *   distributionpoint          [0] distributionpointname optional, 
 *   onlycontainsusercerts      [1] boolean default false, 
 *   onlycontainscacerts        [2] boolean default false, 
 *   onlysomereasons            [3] reasonflags optional, 
 *   indirectcrl                [4] boolean default false,
 *   onlycontainsattributecerts [5] boolean default false }
 * </pre>
 */
public class issuingdistributionpoint
    extends asn1object
{
    private distributionpointname distributionpoint;

    private boolean onlycontainsusercerts;

    private boolean onlycontainscacerts;

    private reasonflags onlysomereasons;

    private boolean indirectcrl;

    private boolean onlycontainsattributecerts;

    private asn1sequence seq;

    public static issuingdistributionpoint getinstance(
        asn1taggedobject obj,
        boolean explicit)
    {
        return getinstance(asn1sequence.getinstance(obj, explicit));
    }

    public static issuingdistributionpoint getinstance(
        object obj)
    {
        if (obj instanceof issuingdistributionpoint)
        {
            return (issuingdistributionpoint)obj;
        }
        else if (obj != null)
        {
            return new issuingdistributionpoint(asn1sequence.getinstance(obj));
        }

        return null;
    }

    /**
     * constructor from given details.
     * 
     * @param distributionpoint
     *            may contain an uri as pointer to most current crl.
     * @param onlycontainsusercerts covers revocation information for end certificates.
     * @param onlycontainscacerts covers revocation information for ca certificates.
     * 
     * @param onlysomereasons
     *            which revocation reasons does this point cover.
     * @param indirectcrl
     *            if <code>true</code> then the crl contains revocation
     *            information about certificates ssued by other cas.
     * @param onlycontainsattributecerts covers revocation information for attribute certificates.
     */
    public issuingdistributionpoint(
        distributionpointname distributionpoint,
        boolean onlycontainsusercerts,
        boolean onlycontainscacerts,
        reasonflags onlysomereasons,
        boolean indirectcrl,
        boolean onlycontainsattributecerts)
    {
        this.distributionpoint = distributionpoint;
        this.indirectcrl = indirectcrl;
        this.onlycontainsattributecerts = onlycontainsattributecerts;
        this.onlycontainscacerts = onlycontainscacerts;
        this.onlycontainsusercerts = onlycontainsusercerts;
        this.onlysomereasons = onlysomereasons;

        asn1encodablevector vec = new asn1encodablevector();
        if (distributionpoint != null)
        {                                    // choice item so explicitly tagged
            vec.add(new dertaggedobject(true, 0, distributionpoint));
        }
        if (onlycontainsusercerts)
        {
            vec.add(new dertaggedobject(false, 1, asn1boolean.getinstance(true)));
        }
        if (onlycontainscacerts)
        {
            vec.add(new dertaggedobject(false, 2, asn1boolean.getinstance(true)));
        }
        if (onlysomereasons != null)
        {
            vec.add(new dertaggedobject(false, 3, onlysomereasons));
        }
        if (indirectcrl)
        {
            vec.add(new dertaggedobject(false, 4, asn1boolean.getinstance(true)));
        }
        if (onlycontainsattributecerts)
        {
            vec.add(new dertaggedobject(false, 5, asn1boolean.getinstance(true)));
        }

        seq = new dersequence(vec);
    }

    /**
     * shorthand constructor from given details.
     *
     * @param distributionpoint
     *            may contain an uri as pointer to most current crl.
     * @param indirectcrl
     *            if <code>true</code> then the crl contains revocation
     *            information about certificates ssued by other cas.
     * @param onlycontainsattributecerts covers revocation information for attribute certificates.
     */
    public issuingdistributionpoint(
        distributionpointname distributionpoint,
        boolean indirectcrl,
        boolean onlycontainsattributecerts)
    {
        this(distributionpoint, false, false, null, indirectcrl, onlycontainsattributecerts);
    }

    /**
     * constructor from asn1sequence
     */
    private issuingdistributionpoint(
        asn1sequence seq)
    {
        this.seq = seq;

        for (int i = 0; i != seq.size(); i++)
        {
            asn1taggedobject o = asn1taggedobject.getinstance(seq.getobjectat(i));

            switch (o.gettagno())
            {
            case 0:
                                                    // choice so explicit
                distributionpoint = distributionpointname.getinstance(o, true);
                break;
            case 1:
                onlycontainsusercerts = asn1boolean.getinstance(o, false).istrue();
                break;
            case 2:
                onlycontainscacerts = asn1boolean.getinstance(o, false).istrue();
                break;
            case 3:
                onlysomereasons = new reasonflags(reasonflags.getinstance(o, false));
                break;
            case 4:
                indirectcrl = asn1boolean.getinstance(o, false).istrue();
                break;
            case 5:
                onlycontainsattributecerts = asn1boolean.getinstance(o, false).istrue();
                break;
            default:
                throw new illegalargumentexception(
                        "unknown tag in issuingdistributionpoint");
            }
        }
    }

    public boolean onlycontainsusercerts()
    {
        return onlycontainsusercerts;
    }

    public boolean onlycontainscacerts()
    {
        return onlycontainscacerts;
    }

    public boolean isindirectcrl()
    {
        return indirectcrl;
    }

    public boolean onlycontainsattributecerts()
    {
        return onlycontainsattributecerts;
    }

    /**
     * @return returns the distributionpoint.
     */
    public distributionpointname getdistributionpoint()
    {
        return distributionpoint;
    }

    /**
     * @return returns the onlysomereasons.
     */
    public reasonflags getonlysomereasons()
    {
        return onlysomereasons;
    }

    public asn1primitive toasn1primitive()
    {
        return seq;
    }

    public string tostring()
    {
        string       sep = system.getproperty("line.separator");
        stringbuffer buf = new stringbuffer();

        buf.append("issuingdistributionpoint: [");
        buf.append(sep);
        if (distributionpoint != null)
        {
            appendobject(buf, sep, "distributionpoint", distributionpoint.tostring());
        }
        if (onlycontainsusercerts)
        {
            appendobject(buf, sep, "onlycontainsusercerts", booleantostring(onlycontainsusercerts));
        }
        if (onlycontainscacerts)
        {
            appendobject(buf, sep, "onlycontainscacerts", booleantostring(onlycontainscacerts));
        }
        if (onlysomereasons != null)
        {
            appendobject(buf, sep, "onlysomereasons", onlysomereasons.tostring());
        }
        if (onlycontainsattributecerts)
        {
            appendobject(buf, sep, "onlycontainsattributecerts", booleantostring(onlycontainsattributecerts));
        }
        if (indirectcrl)
        {
            appendobject(buf, sep, "indirectcrl", booleantostring(indirectcrl));
        }
        buf.append("]");
        buf.append(sep);
        return buf.tostring();
    }

    private void appendobject(stringbuffer buf, string sep, string name, string value)
    {
        string       indent = "    ";

        buf.append(indent);
        buf.append(name);
        buf.append(":");
        buf.append(sep);
        buf.append(indent);
        buf.append(indent);
        buf.append(value);
        buf.append(sep);
    }

    private string booleantostring(boolean value)
    {
        return value ? "true" : "false";
    }
}
