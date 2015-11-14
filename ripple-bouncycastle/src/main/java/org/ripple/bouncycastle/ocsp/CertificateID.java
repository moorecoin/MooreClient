package org.ripple.bouncycastle.ocsp;

import java.math.biginteger;
import java.security.messagedigest;
import java.security.publickey;
import java.security.cert.x509certificate;

import org.ripple.bouncycastle.asn1.asn1inputstream;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.dernull;
import org.ripple.bouncycastle.asn1.derobjectidentifier;
import org.ripple.bouncycastle.asn1.deroctetstring;
import org.ripple.bouncycastle.asn1.ocsp.certid;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;
import org.ripple.bouncycastle.asn1.x509.subjectpublickeyinfo;
import org.ripple.bouncycastle.jce.principalutil;
import org.ripple.bouncycastle.jce.x509principal;

public class certificateid
{
    public static final string hash_sha1 = "1.3.14.3.2.26";

    private final certid id;

    public certificateid(
        certid id)
    {
        if (id == null)
        {
            throw new illegalargumentexception("'id' cannot be null");
        }
        this.id = id;
    }

    /**
     * create from an issuer certificate and the serial number of the
     * certificate it signed.
     *
     * @param hashalgorithm hash algorithm to use
     * @param issuercert issuing certificate
     * @param number serial number
     * @param provider provider to use for hashalgorithm, null if the default one should be used.
     *
     * @exception ocspexception if any problems occur creating the id fields.
     */
    public certificateid(
        string          hashalgorithm,
        x509certificate issuercert,
        biginteger      number,
        string          provider)
        throws ocspexception
    {
        algorithmidentifier hashalg = new algorithmidentifier(
            new derobjectidentifier(hashalgorithm), dernull.instance);

        this.id = createcertid(hashalg, issuercert, new asn1integer(number), provider);
    }

    /**
     * create using the bc provider
     */
    public certificateid(
        string          hashalgorithm,
        x509certificate issuercert,
        biginteger      number)
        throws ocspexception
    {
        this(hashalgorithm, issuercert, number, "bc");
    }

    public string gethashalgoid()
    {
        return id.gethashalgorithm().getobjectid().getid();
    }

    public byte[] getissuernamehash()
    {
        return id.getissuernamehash().getoctets();
    }

    public byte[] getissuerkeyhash()
    {
        return id.getissuerkeyhash().getoctets();
    }

    /**
     * return the serial number for the certificate associated
     * with this request.
     */
    public biginteger getserialnumber()
    {
        return id.getserialnumber().getvalue();
    }

    public boolean matchesissuer(x509certificate issuercert, string provider)
        throws ocspexception
    {
        return createcertid(id.gethashalgorithm(), issuercert, id.getserialnumber(), provider)
            .equals(id);
    }

    public certid toasn1object()
    {
        return id;
    }

    public boolean equals(
        object  o)
    {
        if (!(o instanceof certificateid))
        {
            return false;
        }

        certificateid   obj = (certificateid)o;

        return id.toasn1primitive().equals(obj.id.toasn1primitive());
    }

    public int hashcode()
    {
        return id.toasn1primitive().hashcode();
    }

    /**
     * create a new certificateid for a new serial number derived from a previous one
     * calculated for the same ca certificate.
     *
     * @param original the previously calculated certificateid for the ca.
     * @param newserialnumber the serial number for the new certificate of interest.
     *
     * @return a new certificateid for newserialnumber
     */
    public static certificateid derivecertificateid(certificateid original, biginteger newserialnumber)
    {
        return new certificateid(new certid(original.id.gethashalgorithm(), original.id.getissuernamehash(), original.id.getissuerkeyhash(), new asn1integer(newserialnumber)));
    }

    private static certid createcertid(algorithmidentifier hashalg, x509certificate issuercert,
        asn1integer serialnumber, string provider)
        throws ocspexception
    {
        try
        {
            messagedigest digest = ocsputil.createdigestinstance(hashalg.getalgorithm() .getid(),
                provider);

            x509principal issuername = principalutil.getsubjectx509principal(issuercert);

            digest.update(issuername.getencoded());

            asn1octetstring issuernamehash = new deroctetstring(digest.digest());
            publickey issuerkey = issuercert.getpublickey();

            asn1inputstream ain = new asn1inputstream(issuerkey.getencoded());
            subjectpublickeyinfo info = subjectpublickeyinfo.getinstance(ain.readobject());

            digest.update(info.getpublickeydata().getbytes());

            asn1octetstring issuerkeyhash = new deroctetstring(digest.digest());

            return new certid(hashalg, issuernamehash, issuerkeyhash, serialnumber);
        }
        catch (exception e)
        {
            throw new ocspexception("problem creating id: " + e, e);
        }
    }
}
