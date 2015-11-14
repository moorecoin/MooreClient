package org.ripple.bouncycastle.asn1.dvcs;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1set;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
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

public class dvcscertinfo
    extends asn1object
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

    public dvcscertinfo(
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

    private dvcscertinfo(asn1sequence seq)
    {
        int i = 0;
        asn1encodable x = seq.getobjectat(i++);
        try
        {
            asn1integer encversion = asn1integer.getinstance(x);
            this.version = encversion.getvalue().intvalue();
            x = seq.getobjectat(i++);
        }
        catch (illegalargumentexception e)
        {
        }

        this.dvreqinfo = dvcsrequestinformation.getinstance(x);
        x = seq.getobjectat(i++);
        this.messageimprint = digestinfo.getinstance(x);
        x = seq.getobjectat(i++);
        this.serialnumber = asn1integer.getinstance(x);
        x = seq.getobjectat(i++);
        this.responsetime = dvcstime.getinstance(x);

        while (i < seq.size())
        {

            x = seq.getobjectat(i++);

            try
            {
                asn1taggedobject t = asn1taggedobject.getinstance(x);
                int tagno = t.gettagno();

                switch (tagno)
                {
                case tag_dv_status:
                    this.dvstatus = pkistatusinfo.getinstance(t, false);
                    break;
                case tag_policy:
                    this.policy = policyinformation.getinstance(asn1sequence.getinstance(t, false));
                    break;
                case tag_req_signature:
                    this.reqsignature = asn1set.getinstance(t, false);
                    break;
                case tag_certs:
                    this.certs = asn1sequence.getinstance(t, false);
                    break;
                }

                continue;

            }
            catch (illegalargumentexception e)
            {
            }

            try
            {
                this.extensions = extensions.getinstance(x);
            }
            catch (illegalargumentexception e)
            {
            }

        }

    }

    public static dvcscertinfo getinstance(object obj)
    {
        if (obj instanceof dvcscertinfo)
        {
            return (dvcscertinfo)obj;
        }
        else if (obj != null)
        {
            return new dvcscertinfo(asn1sequence.getinstance(obj));
        }

        return null;
    }

    public static dvcscertinfo getinstance(
        asn1taggedobject obj,
        boolean explicit)
    {
        return getinstance(asn1sequence.getinstance(obj, explicit));
    }

    public asn1primitive toasn1primitive()
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

        return new dersequence(v);
    }

    public string tostring()
    {
        stringbuffer s = new stringbuffer();

        s.append("dvcscertinfo {\n");

        if (version != default_version)
        {
            s.append("version: " + version + "\n");
        }
        s.append("dvreqinfo: " + dvreqinfo + "\n");
        s.append("messageimprint: " + messageimprint + "\n");
        s.append("serialnumber: " + serialnumber + "\n");
        s.append("responsetime: " + responsetime + "\n");
        if (dvstatus != null)
        {
            s.append("dvstatus: " + dvstatus + "\n");
        }
        if (policy != null)
        {
            s.append("policy: " + policy + "\n");
        }
        if (reqsignature != null)
        {
            s.append("reqsignature: " + reqsignature + "\n");
        }
        if (certs != null)
        {
            s.append("certs: " + certs + "\n");
        }
        if (extensions != null)
        {
            s.append("extensions: " + extensions + "\n");
        }

        s.append("}\n");
        return s.tostring();
    }

    public int getversion()
    {
        return version;
    }

    private void setversion(int version)
    {
        this.version = version;
    }

    public dvcsrequestinformation getdvreqinfo()
    {
        return dvreqinfo;
    }

    private void setdvreqinfo(dvcsrequestinformation dvreqinfo)
    {
        this.dvreqinfo = dvreqinfo;
    }

    public digestinfo getmessageimprint()
    {
        return messageimprint;
    }

    private void setmessageimprint(digestinfo messageimprint)
    {
        this.messageimprint = messageimprint;
    }

    public asn1integer getserialnumber()
    {
        return serialnumber;
    }

    public dvcstime getresponsetime()
    {
        return responsetime;
    }

    public pkistatusinfo getdvstatus()
    {
        return dvstatus;
    }

    public policyinformation getpolicy()
    {
        return policy;
    }

    public asn1set getreqsignature()
    {
        return reqsignature;
    }

    public targetetcchain[] getcerts()
    {
        if (certs != null)
        {
            return targetetcchain.arrayfromsequence(certs);
        }

        return null;
    }

    public extensions getextensions()
    {
        return extensions;
    }
}
