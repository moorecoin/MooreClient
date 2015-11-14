package org.ripple.bouncycastle.asn1.x509;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1generalizedtime;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.derbitstring;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.derset;

/**
 * generator for version 2 attributecertificateinfo
 * <pre>
 * attributecertificateinfo ::= sequence {
 *       version              attcertversion -- version is v2,
 *       holder               holder,
 *       issuer               attcertissuer,
 *       signature            algorithmidentifier,
 *       serialnumber         certificateserialnumber,
 *       attrcertvalidityperiod   attcertvalidityperiod,
 *       attributes           sequence of attribute,
 *       issueruniqueid       uniqueidentifier optional,
 *       extensions           extensions optional
 * }
 * </pre>
 *
 */
public class v2attributecertificateinfogenerator
{
    private asn1integer version;
    private holder holder;
    private attcertissuer issuer;
    private algorithmidentifier signature;
    private asn1integer serialnumber;
    private asn1encodablevector attributes;
    private derbitstring issueruniqueid;
    private extensions extensions;

    // note: validity period start/end dates stored directly
    //private attcertvalidityperiod attrcertvalidityperiod;
    private asn1generalizedtime startdate, enddate; 

    public v2attributecertificateinfogenerator()
    {
        this.version = new asn1integer(1);
        attributes = new asn1encodablevector();
    }
    
    public void setholder(holder holder)
    {
        this.holder = holder;
    }
    
    public void addattribute(string oid, asn1encodable value) 
    {
        attributes.add(new attribute(new asn1objectidentifier(oid), new derset(value)));
    }

    /**
     * @param attribute
     */
    public void addattribute(attribute attribute)
    {
        attributes.add(attribute);
    }
    
    public void setserialnumber(
        asn1integer  serialnumber)
    {
        this.serialnumber = serialnumber;
    }

    public void setsignature(
        algorithmidentifier    signature)
    {
        this.signature = signature;
    }

    public void setissuer(
        attcertissuer    issuer)
    {
        this.issuer = issuer;
    }

    public void setstartdate(
        asn1generalizedtime startdate)
    {
        this.startdate = startdate;
    }

    public void setenddate(
        asn1generalizedtime enddate)
    {
        this.enddate = enddate;
    }

    public void setissueruniqueid(
        derbitstring    issueruniqueid)
    {
        this.issueruniqueid = issueruniqueid;
    }

    /**
     * @deprecated use method taking extensions
     * @param extensions
     */
    public void setextensions(
        x509extensions    extensions)
    {
        this.extensions = extensions.getinstance(extensions.toasn1primitive());
    }

    public void setextensions(
        extensions    extensions)
    {
        this.extensions = extensions;
    }

    public attributecertificateinfo generateattributecertificateinfo()
    {
        if ((serialnumber == null) || (signature == null)
            || (issuer == null) || (startdate == null) || (enddate == null)
            || (holder == null) || (attributes == null))
        {
            throw new illegalstateexception("not all mandatory fields set in v2 attributecertificateinfo generator");
        }

        asn1encodablevector  v = new asn1encodablevector();

        v.add(version);
        v.add(holder);
        v.add(issuer);
        v.add(signature);
        v.add(serialnumber);
    
        //
        // before and after dates => attcertvalidityperiod
        //
        attcertvalidityperiod validity = new attcertvalidityperiod(startdate, enddate);
        v.add(validity);
        
        // attributes
        v.add(new dersequence(attributes));
        
        if (issueruniqueid != null)
        {
            v.add(issueruniqueid);
        }
    
        if (extensions != null)
        {
            v.add(extensions);
        }

        return attributecertificateinfo.getinstance(new dersequence(v));
    }
}
