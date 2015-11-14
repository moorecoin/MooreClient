package org.ripple.bouncycastle.asn1.pkcs;

import java.math.biginteger;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.x500.x500name;
import org.ripple.bouncycastle.asn1.x509.x509name;

public class issuerandserialnumber
    extends asn1object
{
    x500name name;
    asn1integer  certserialnumber;

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

    private issuerandserialnumber(
        asn1sequence    seq)
    {
        this.name = x500name.getinstance(seq.getobjectat(0));
        this.certserialnumber = (asn1integer)seq.getobjectat(1);
    }

    public issuerandserialnumber(
        x509name    name,
        biginteger  certserialnumber)
    {
        this.name = x500name.getinstance(name.toasn1primitive());
        this.certserialnumber = new asn1integer(certserialnumber);
    }

    public issuerandserialnumber(
        x509name    name,
        asn1integer  certserialnumber)
    {
        this.name = x500name.getinstance(name.toasn1primitive());
        this.certserialnumber = certserialnumber;
    }

    public issuerandserialnumber(
        x500name    name,
        biginteger  certserialnumber)
    {
        this.name = name;
        this.certserialnumber = new asn1integer(certserialnumber);
    }

    public x500name getname()
    {
        return name;
    }

    public asn1integer getcertificateserialnumber()
    {
        return certserialnumber;
    }

    public asn1primitive toasn1primitive()
    {
        asn1encodablevector    v = new asn1encodablevector();

        v.add(name);
        v.add(certserialnumber);

        return new dersequence(v);
    }
}
