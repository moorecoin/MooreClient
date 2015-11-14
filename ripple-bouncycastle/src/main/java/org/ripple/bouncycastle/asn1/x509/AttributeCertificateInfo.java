package org.ripple.bouncycastle.asn1.x509;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.derbitstring;
import org.ripple.bouncycastle.asn1.dersequence;

public class attributecertificateinfo
    extends asn1object
{
    private asn1integer              version;
    private holder                  holder;
    private attcertissuer           issuer;
    private algorithmidentifier     signature;
    private asn1integer              serialnumber;
    private attcertvalidityperiod   attrcertvalidityperiod;
    private asn1sequence            attributes;
    private derbitstring            issueruniqueid;
    private extensions              extensions;

    public static attributecertificateinfo getinstance(
        asn1taggedobject obj,
        boolean          explicit)
    {
        return getinstance(asn1sequence.getinstance(obj, explicit));
    }

    public static attributecertificateinfo getinstance(
        object  obj)
    {
        if (obj instanceof attributecertificateinfo)
        {
            return (attributecertificateinfo)obj;
        }
        else if (obj != null)
        {
            return new attributecertificateinfo(asn1sequence.getinstance(obj));
        }

        return null;
    }

    private attributecertificateinfo(
        asn1sequence   seq)
    {
        if (seq.size() < 7 || seq.size() > 9)
        {
            throw new illegalargumentexception("bad sequence size: " + seq.size());
        }

        this.version = asn1integer.getinstance(seq.getobjectat(0));
        this.holder = holder.getinstance(seq.getobjectat(1));
        this.issuer = attcertissuer.getinstance(seq.getobjectat(2));
        this.signature = algorithmidentifier.getinstance(seq.getobjectat(3));
        this.serialnumber = asn1integer.getinstance(seq.getobjectat(4));
        this.attrcertvalidityperiod = attcertvalidityperiod.getinstance(seq.getobjectat(5));
        this.attributes = asn1sequence.getinstance(seq.getobjectat(6));
        
        for (int i = 7; i < seq.size(); i++)
        {
            asn1encodable    obj = (asn1encodable)seq.getobjectat(i);

            if (obj instanceof derbitstring)
            {
                this.issueruniqueid = derbitstring.getinstance(seq.getobjectat(i));
            }
            else if (obj instanceof asn1sequence || obj instanceof extensions)
            {
                this.extensions = extensions.getinstance(seq.getobjectat(i));
            }
        }
    }
    
    public asn1integer getversion()
    {
        return version;
    }

    public holder getholder()
    {
        return holder;
    }

    public attcertissuer getissuer()
    {
        return issuer;
    }

    public algorithmidentifier getsignature()
    {
        return signature;
    }

    public asn1integer getserialnumber()
    {
        return serialnumber;
    }

    public attcertvalidityperiod getattrcertvalidityperiod()
    {
        return attrcertvalidityperiod;
    }

    public asn1sequence getattributes()
    {
        return attributes;
    }

    public derbitstring getissueruniqueid()
    {
        return issueruniqueid;
    }

    public extensions getextensions()
    {
        return extensions;
    }

    /**
     * produce an object suitable for an asn1outputstream.
     * <pre>
     *  attributecertificateinfo ::= sequence {
     *       version              attcertversion -- version is v2,
     *       holder               holder,
     *       issuer               attcertissuer,
     *       signature            algorithmidentifier,
     *       serialnumber         certificateserialnumber,
     *       attrcertvalidityperiod   attcertvalidityperiod,
     *       attributes           sequence of attribute,
     *       issueruniqueid       uniqueidentifier optional,
     *       extensions           extensions optional
     *  }
     *
     *  attcertversion ::= integer { v2(1) }
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector  v = new asn1encodablevector();

        v.add(version);
        v.add(holder);
        v.add(issuer);
        v.add(signature);
        v.add(serialnumber);
        v.add(attrcertvalidityperiod);
        v.add(attributes);
        
        if (issueruniqueid != null)
        {
            v.add(issueruniqueid);
        }
        
        if (extensions != null)
        {
            v.add(extensions);
        }
        
        return new dersequence(v);
    }
}
