package org.ripple.bouncycastle.asn1.crmf;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;

public class certrequest
    extends asn1object
{
    private asn1integer certreqid;
    private certtemplate certtemplate;
    private controls controls;

    private certrequest(asn1sequence seq)
    {
        certreqid = new asn1integer(asn1integer.getinstance(seq.getobjectat(0)).getvalue());
        certtemplate = certtemplate.getinstance(seq.getobjectat(1));
        if (seq.size() > 2)
        {
            controls = controls.getinstance(seq.getobjectat(2));
        }
    }

    public static certrequest getinstance(object o)
    {
        if (o instanceof certrequest)
        {
            return (certrequest)o;
        }
        else if (o != null)
        {
            return new certrequest(asn1sequence.getinstance(o));
        }

        return null;
    }

    public certrequest(
        int certreqid,
        certtemplate certtemplate,
        controls controls)
    {
        this(new asn1integer(certreqid), certtemplate, controls);
    }

    public certrequest(
        asn1integer certreqid,
        certtemplate certtemplate,
        controls controls)
    {
        this.certreqid = certreqid;
        this.certtemplate = certtemplate;
        this.controls = controls;
    }

    public asn1integer getcertreqid()
    {
        return certreqid;
    }

    public certtemplate getcerttemplate()
    {
        return certtemplate;
    }

    public controls getcontrols()
    {
        return controls;
    }

    /**
     * <pre>
     * certrequest ::= sequence {
     *                      certreqid     integer,          -- id for matching request and reply
     *                      certtemplate  certtemplate,  -- selected fields of cert to be issued
     *                      controls      controls optional }   -- attributes affecting issuance
     * </pre>
     * @return a basic asn.1 object representation.
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        v.add(certreqid);
        v.add(certtemplate);

        if (controls != null)
        {
            v.add(controls);
        }

        return new dersequence(v);
    }
}
