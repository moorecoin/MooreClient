package org.ripple.bouncycastle.asn1.dvcs;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1set;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;
import org.ripple.bouncycastle.asn1.cmp.pkistatusinfo;
import org.ripple.bouncycastle.asn1.x509.digestinfo;
import org.ripple.bouncycastle.asn1.x509.extensions;
import org.ripple.bouncycastle.asn1.x509.policyinformation;

/**
 * <pre>
 *     dvcscertinfo::= sequence  {
 *         version             integer default 1 ,
 *         dvreqinfo           dvcsrequestinformation,
 *         messageimprint      digestinfo,
 *         serialnumber        integer,
 *         responsetime        dvcstime,
 *         dvstatus            [0] pkistatusinfo optional,
 *         policy              [1] policyinformation optional,
 *         reqsignature        [2] signerinfos  optional,
 *         certs               [3] sequence size (1..max) of
 *                                 targetetcchain optional,
 *         extensions          extensions optional
 *     }
 * </pre>
 */

public class dvcscertinfobuilder
{

    private int version = default_version;
    private dvcsrequestinformation dvreqinfo;
    private digestinfo messageimprint;
    private asn1integer serialnumber;
    private dvcstime responsetime;
    private pkistatusinfo dvstatus;
    private policyinformation policy;
    private asn1set reqsignature;
    private asn1sequence certs;
    private extensions extensions;

    private static final int default_version = 1;
    private static final int tag_dv_status = 0;
    private static final int tag_policy = 1;
    private static final int tag_req_signature = 2;
    private static final int tag_certs = 3;

    public dvcscertinfobuilder(
        dvcsrequestinformation dvreqinfo,
        digestinfo messageimprint,
        asn1integer serialnumber,
        dvcstime responsetime)
    {
        this.dvreqinfo = dvreqinfo;
        this.messageimprint = messageimprint;
        this.serialnumber = serialnumber;
        this.responsetime = responsetime;
    }

    public dvcscertinfo build()
    {

        asn1encodablevector v = new asn1encodablevector();

        if (version != default_version)
        {
            v.add(new asn1integer(version));
        }
        v.add(dvreqinfo);
        v.add(messageimprint);
        v.add(serialnumber);
        v.add(responsetime);
        if (dvstatus != null)
        {
            v.add(new dertaggedobject(false, tag_dv_status, dvstatus));
        }
        if (policy != null)
        {
            v.add(new dertaggedobject(false, tag_policy, policy));
        }
        if (reqsignature != null)
        {
            v.add(new dertaggedobject(false, tag_req_signature, reqsignature));
        }
        if (certs != null)
        {
            v.add(new dertaggedobject(false, tag_certs, certs));
        }
        if (extensions != null)
        {
            v.add(extensions);
        }

        return dvcscertinfo.getinstance(new dersequence(v));
    }

    public void setversion(int version)
    {
        this.version = version;
    }

    public void setdvreqinfo(dvcsrequestinformation dvreqinfo)
    {
        this.dvreqinfo = dvreqinfo;
    }

    public void setmessageimprint(digestinfo messageimprint)
    {
        this.messageimprint = messageimprint;
    }

    public void setserialnumber(asn1integer serialnumber)
    {
        this.serialnumber = serialnumber;
    }

    public void setresponsetime(dvcstime responsetime)
    {
        this.responsetime = responsetime;
    }

    public void setdvstatus(pkistatusinfo dvstatus)
    {
        this.dvstatus = dvstatus;
    }

    public void setpolicy(policyinformation policy)
    {
        this.policy = policy;
    }

    public void setreqsignature(asn1set reqsignature)
    {
        this.reqsignature = reqsignature;
    }

    public void setcerts(targetetcchain[] certs)
    {
        this.certs = new dersequence(certs);
    }

    public void setextensions(extensions extensions)
    {
        this.extensions = extensions;
    }

}
