package org.ripple.bouncycastle.asn1.x509;

import java.io.ioexception;

import org.ripple.bouncycastle.asn1.asn1boolean;
import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.deroctetstring;
import org.ripple.bouncycastle.asn1.dersequence;

/**
 * an object for the elements in the x.509 v3 extension block.
 */
public class extension
    extends asn1object
{
    /**
     * subject directory attributes
     */
    public static final asn1objectidentifier subjectdirectoryattributes = new asn1objectidentifier("2.5.29.9");
    
    /**
     * subject key identifier 
     */
    public static final asn1objectidentifier subjectkeyidentifier = new asn1objectidentifier("2.5.29.14");

    /**
     * key usage 
     */
    public static final asn1objectidentifier keyusage = new asn1objectidentifier("2.5.29.15");

    /**
     * private key usage period 
     */
    public static final asn1objectidentifier privatekeyusageperiod = new asn1objectidentifier("2.5.29.16");

    /**
     * subject alternative name 
     */
    public static final asn1objectidentifier subjectalternativename = new asn1objectidentifier("2.5.29.17");

    /**
     * issuer alternative name 
     */
    public static final asn1objectidentifier issueralternativename = new asn1objectidentifier("2.5.29.18");

    /**
     * basic constraints 
     */
    public static final asn1objectidentifier basicconstraints = new asn1objectidentifier("2.5.29.19");

    /**
     * crl number 
     */
    public static final asn1objectidentifier crlnumber = new asn1objectidentifier("2.5.29.20");

    /**
     * reason code 
     */
    public static final asn1objectidentifier reasoncode = new asn1objectidentifier("2.5.29.21");

    /**
     * hold instruction code 
     */
    public static final asn1objectidentifier instructioncode = new asn1objectidentifier("2.5.29.23");

    /**
     * invalidity date 
     */
    public static final asn1objectidentifier invaliditydate = new asn1objectidentifier("2.5.29.24");

    /**
     * delta crl indicator 
     */
    public static final asn1objectidentifier deltacrlindicator = new asn1objectidentifier("2.5.29.27");

    /**
     * issuing distribution point 
     */
    public static final asn1objectidentifier issuingdistributionpoint = new asn1objectidentifier("2.5.29.28");

    /**
     * certificate issuer 
     */
    public static final asn1objectidentifier certificateissuer = new asn1objectidentifier("2.5.29.29");

    /**
     * name constraints 
     */
    public static final asn1objectidentifier nameconstraints = new asn1objectidentifier("2.5.29.30");

    /**
     * crl distribution points 
     */
    public static final asn1objectidentifier crldistributionpoints = new asn1objectidentifier("2.5.29.31");

    /**
     * certificate policies 
     */
    public static final asn1objectidentifier certificatepolicies = new asn1objectidentifier("2.5.29.32");

    /**
     * policy mappings 
     */
    public static final asn1objectidentifier policymappings = new asn1objectidentifier("2.5.29.33");

    /**
     * authority key identifier 
     */
    public static final asn1objectidentifier authoritykeyidentifier = new asn1objectidentifier("2.5.29.35");

    /**
     * policy constraints 
     */
    public static final asn1objectidentifier policyconstraints = new asn1objectidentifier("2.5.29.36");

    /**
     * extended key usage 
     */
    public static final asn1objectidentifier extendedkeyusage = new asn1objectidentifier("2.5.29.37");

    /**
     * freshest crl
     */
    public static final asn1objectidentifier freshestcrl = new asn1objectidentifier("2.5.29.46");
     
    /**
     * inhibit any policy
     */
    public static final asn1objectidentifier inhibitanypolicy = new asn1objectidentifier("2.5.29.54");

    /**
     * authority info access
     */
    public static final asn1objectidentifier authorityinfoaccess = new asn1objectidentifier("1.3.6.1.5.5.7.1.1");

    /**
     * subject info access
     */
    public static final asn1objectidentifier subjectinfoaccess = new asn1objectidentifier("1.3.6.1.5.5.7.1.11");
    
    /**
     * logo type
     */
    public static final asn1objectidentifier logotype = new asn1objectidentifier("1.3.6.1.5.5.7.1.12");

    /**
     * biometricinfo
     */
    public static final asn1objectidentifier biometricinfo = new asn1objectidentifier("1.3.6.1.5.5.7.1.2");
    
    /**
     * qcstatements
     */
    public static final asn1objectidentifier qcstatements = new asn1objectidentifier("1.3.6.1.5.5.7.1.3");

    /**
     * audit identity extension in attribute certificates.
     */
    public static final asn1objectidentifier auditidentity = new asn1objectidentifier("1.3.6.1.5.5.7.1.4");
    
    /**
     * norevavail extension in attribute certificates.
     */
    public static final asn1objectidentifier norevavail = new asn1objectidentifier("2.5.29.56");

    /**
     * targetinformation extension in attribute certificates.
     */
    public static final asn1objectidentifier targetinformation = new asn1objectidentifier("2.5.29.55");

    private asn1objectidentifier extnid;
    private boolean             critical;
    private asn1octetstring      value;

    public extension(
        asn1objectidentifier extnid,
        asn1boolean critical,
        asn1octetstring value)
    {
        this(extnid, critical.istrue(), value);
    }

    public extension(
        asn1objectidentifier extnid,
        boolean critical,
        byte[] value)
    {
        this(extnid, critical, new deroctetstring(value));
    }

    public extension(
        asn1objectidentifier extnid,
        boolean critical,
        asn1octetstring value)
    {
        this.extnid = extnid;
        this.critical = critical;
        this.value = value;
    }

    private extension(asn1sequence seq)
    {
        if (seq.size() == 2)
        {
            this.extnid = asn1objectidentifier.getinstance(seq.getobjectat(0));
            this.critical = false;
            this.value = asn1octetstring.getinstance(seq.getobjectat(1));
        }
        else if (seq.size() == 3)
        {
            this.extnid = asn1objectidentifier.getinstance(seq.getobjectat(0));
            this.critical = asn1boolean.getinstance(seq.getobjectat(1)).istrue();
            this.value = asn1octetstring.getinstance(seq.getobjectat(2));
        }
        else
        {
            throw new illegalargumentexception("bad sequence size: " + seq.size());
        }
    }

    public static extension getinstance(object obj)
    {
        if (obj instanceof extension)
        {
            return (extension)obj;
        }
        else if (obj != null)
        {
            return new extension(asn1sequence.getinstance(obj));
        }

        return null;
    }

    public asn1objectidentifier getextnid()
    {
        return extnid;
    }

    public boolean iscritical()
    {
        return critical;
    }

    public asn1octetstring getextnvalue()
    {
        return value;
    }

    public asn1encodable getparsedvalue()
    {
        return convertvaluetoobject(this);
    }

    public int hashcode()
    {
        if (this.iscritical())
        {
            return this.getextnvalue().hashcode() ^ this.getextnid().hashcode();
        }

        return ~(this.getextnvalue().hashcode() ^ this.getextnid().hashcode());
    }

    public boolean equals(
        object  o)
    {
        if (!(o instanceof extension))
        {
            return false;
        }

        extension other = (extension)o;

        return other.getextnid().equals(this.getextnid())
            && other.getextnvalue().equals(this.getextnvalue())
            && (other.iscritical() == this.iscritical());
    }

    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        v.add(extnid);

        if (critical)
        {
            v.add(asn1boolean.getinstance(true));
        }

        v.add(value);

        return new dersequence(v);
    }

    /**
     * convert the value of the passed in extension to an object
     * @param ext the extension to parse
     * @return the object the value string contains
     * @exception illegalargumentexception if conversion is not possible
     */
    private static asn1primitive convertvaluetoobject(
        extension ext)
        throws illegalargumentexception
    {
        try
        {
            return asn1primitive.frombytearray(ext.getextnvalue().getoctets());
        }
        catch (ioexception e)
        {
            throw new illegalargumentexception("can't convert extension: " +  e);
        }
    }
}
