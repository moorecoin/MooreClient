package org.ripple.bouncycastle.asn1.crmf;

import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.derbitstring;
import org.ripple.bouncycastle.asn1.x500.x500name;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;
import org.ripple.bouncycastle.asn1.x509.extensions;
import org.ripple.bouncycastle.asn1.x509.subjectpublickeyinfo;

public class certtemplate
    extends asn1object
{
    private asn1sequence seq;

    private asn1integer version;
    private asn1integer serialnumber;
    private algorithmidentifier signingalg;
    private x500name issuer;
    private optionalvalidity validity;
    private x500name subject;
    private subjectpublickeyinfo publickey;
    private derbitstring issueruid;
    private derbitstring subjectuid;
    private extensions extensions;

    private certtemplate(asn1sequence seq)
    {
        this.seq = seq;

        enumeration en = seq.getobjects();
        while (en.hasmoreelements())
        {
            asn1taggedobject tobj = (asn1taggedobject)en.nextelement();

            switch (tobj.gettagno())
            {
            case 0:
                version = asn1integer.getinstance(tobj, false);
                break;
            case 1:
                serialnumber = asn1integer.getinstance(tobj, false);
                break;
            case 2:
                signingalg = algorithmidentifier.getinstance(tobj, false);
                break;
            case 3:
                issuer = x500name.getinstance(tobj, true); // choice
                break;
            case 4:
                validity = optionalvalidity.getinstance(asn1sequence.getinstance(tobj, false));
                break;
            case 5:
                subject = x500name.getinstance(tobj, true); // choice
                break;
            case 6:
                publickey = subjectpublickeyinfo.getinstance(tobj, false);
                break;
            case 7:
                issueruid = derbitstring.getinstance(tobj, false);
                break;
            case 8:
                subjectuid = derbitstring.getinstance(tobj, false);
                break;
            case 9:
                extensions = extensions.getinstance(tobj, false);
                break;
            default:
                throw new illegalargumentexception("unknown tag: " + tobj.gettagno());
            }
        }
    }

    public static certtemplate getinstance(object o)
    {
        if (o instanceof certtemplate)
        {
            return (certtemplate)o;
        }
        else if (o != null)
        {
            return new certtemplate(asn1sequence.getinstance(o));
        }

        return null;
    }

    public int getversion()
    {
        return version.getvalue().intvalue();
    }

    public asn1integer getserialnumber()
    {
        return serialnumber;
    }

    public algorithmidentifier getsigningalg()
    {
        return signingalg;
    }

    public x500name getissuer()
    {
        return issuer;
    }

    public optionalvalidity getvalidity()
    {
        return validity;
    }

    public x500name getsubject()
    {
        return subject;
    }

    public subjectpublickeyinfo getpublickey()
    {
        return publickey;
    }

    public derbitstring getissueruid()
    {
        return issueruid;
    }

    public derbitstring getsubjectuid()
    {
        return subjectuid;
    }

    public extensions getextensions()
    {
        return extensions;
    }

    /**
     * <pre>
     *  certtemplate ::= sequence {
     *      version      [0] version               optional,
     *      serialnumber [1] integer               optional,
     *      signingalg   [2] algorithmidentifier   optional,
     *      issuer       [3] name                  optional,
     *      validity     [4] optionalvalidity      optional,
     *      subject      [5] name                  optional,
     *      publickey    [6] subjectpublickeyinfo  optional,
     *      issueruid    [7] uniqueidentifier      optional,
     *      subjectuid   [8] uniqueidentifier      optional,
     *      extensions   [9] extensions            optional }
     * </pre>
     * @return a basic asn.1 object representation.
     */
    public asn1primitive toasn1primitive()
    {
        return seq;
    }
}
