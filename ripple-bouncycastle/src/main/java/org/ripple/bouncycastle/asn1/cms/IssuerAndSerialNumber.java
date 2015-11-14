package org.ripple.bouncycastle.asn1.cms;

import java.math.biginteger;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.x500.x500name;
import org.ripple.bouncycastle.asn1.x509.certificate;
import org.ripple.bouncycastle.asn1.x509.x509certificatestructure;
import org.ripple.bouncycastle.asn1.x509.x509name;

public class issuerandserialnumber
    extends asn1object
{
    private x500name    name;
    private asn1integer  serialnumber;

    public static issuerandserialnumber getinstance(
        object  obj)
    {
        if (obj instanceof issuerandserialnumber)
        {
            return (issuerandserialnumber)obj;
        }
        else if (obj != null)
        {
            return new issuerandserialnumber(asn1sequence.getinstance(obj));
        }

        return null;
    }

    /**
     * @deprecated  use getinstance() method.
     * @param seq
     */
    public issuerandserialnumber(
        asn1sequence    seq)
    {
        this.name = x500name.getinstance(seq.getobjectat(0));
        this.serialnumber = (asn1integer)seq.getobjectat(1);
    }

    public issuerandserialnumber(
        certificate certificate)
    {
        this.name = certificate.getissuer();
        this.serialnumber = certificate.getserialnumber();
    }

    public issuerandserialnumber(
        x509certificatestructure certificate)
    {
        this.name = certificate.getissuer();
        this.serialnumber = certificate.getserialnumber();
    }

    public issuerandserialnumber(
        x500name name,
        biginteger  serialnumber)
    {
        this.name = name;
        this.serialnumber = new asn1integer(serialnumber);
    }

    /**
     * @deprecated use x500name constructor
     */
    public issuerandserialnumber(
        x509name    name,
        biginteger  serialnumber)
    {
        this.name = x500name.getinstance(name);
        this.serialnumber = new asn1integer(serialnumber);
    }

    /**
     * @deprecated use x500name constructor
     */
    public issuerandserialnumber(
        x509name    name,
        asn1integer  serialnumber)
    {
        this.name = x500name.getinstance(name);
        this.serialnumber = serialnumber;
    }

    public x500name getname()
    {
        return name;
    }

    public asn1integer getserialnumber()
    {
        return serialnumber;
    }

    public asn1primitive toasn1primitive()
    {
        asn1encodablevector    v = new asn1encodablevector();

        v.add(name);
        v.add(serialnumber);

        return new dersequence(v);
    }
}
