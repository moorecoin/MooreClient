package org.ripple.bouncycastle.asn1.dvcs;

import java.math.biginteger;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1generalizedtime;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;
import org.ripple.bouncycastle.asn1.x509.extensions;
import org.ripple.bouncycastle.asn1.x509.generalnames;
import org.ripple.bouncycastle.asn1.x509.policyinformation;

/**
 * <pre>
 *     dvcsrequestinformation ::= sequence  {
 *         version                      integer default 1 ,
 *         service                      servicetype,
 *         nonce                        nonce optional,
 *         requesttime                  dvcstime optional,
 *         requester                    [0] generalnames optional,
 *         requestpolicy                [1] policyinformation optional,
 *         dvcs                         [2] generalnames optional,
 *         datalocations                [3] generalnames optional,
 *         extensions                   [4] implicit extensions optional
 *     }
 * </pre>
 */

public class dvcsrequestinformation
    extends asn1object
{
    private int version = default_version;
    private servicetype service;
    private biginteger nonce;
    private dvcstime requesttime;
    private generalnames requester;
    private policyinformation requestpolicy;
    private generalnames dvcs;
    private generalnames datalocations;
    private extensions extensions;

    private static final int default_version = 1;
    private static final int tag_requester = 0;
    private static final int tag_request_policy = 1;
    private static final int tag_dvcs = 2;
    private static final int tag_data_locations = 3;
    private static final int tag_extensions = 4;

    private dvcsrequestinformation(asn1sequence seq)
    {
        int i = 0;

        if (seq.getobjectat(0) instanceof asn1integer)
        {
            asn1integer encversion = asn1integer.getinstance(seq.getobjectat(i++));
            this.version = encversion.getvalue().intvalue();
        }
        else
        {
            this.version = 1;
        }

        this.service = servicetype.getinstance(seq.getobjectat(i++));

        while (i < seq.size())
        {
            asn1encodable x = seq.getobjectat(i);

            if (x instanceof asn1integer)
            {
                this.nonce = asn1integer.getinstance(x).getvalue();
            }
            else if (x instanceof asn1generalizedtime)
            {
                this.requesttime = dvcstime.getinstance(x);
            }
            else if (x instanceof asn1taggedobject)
            {
                asn1taggedobject t = asn1taggedobject.getinstance(x);
                int tagno = t.gettagno();

                switch (tagno)
                {
                case tag_requester:
                    this.requester = generalnames.getinstance(t, false);
                    break;
                case tag_request_policy:
                    this.requestpolicy = policyinformation.getinstance(asn1sequence.getinstance(t, false));
                    break;
                case tag_dvcs:
                    this.dvcs = generalnames.getinstance(t, false);
                    break;
                case tag_data_locations:
                    this.datalocations = generalnames.getinstance(t, false);
                    break;
                case tag_extensions:
                    this.extensions = extensions.getinstance(t, false);
                    break;
                }
            }
            else
            {
                this.requesttime = dvcstime.getinstance(x);
            }

            i++;
        }
    }

    public static dvcsrequestinformation getinstance(object obj)
    {
        if (obj instanceof dvcsrequestinformation)
        {
            return (dvcsrequestinformation)obj;
        }
        else if (obj != null)
        {
            return new dvcsrequestinformation(asn1sequence.getinstance(obj));
        }

        return null;
    }

    public static dvcsrequestinformation getinstance(
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
        v.add(service);
        if (nonce != null)
        {
            v.add(new asn1integer(nonce));
        }
        if (requesttime != null)
        {
            v.add(requesttime);
        }

        int[] tags = new int[]{
            tag_requester,
            tag_request_policy,
            tag_dvcs,
            tag_data_locations,
            tag_extensions
        };
        asn1encodable[] taggedobjects = new asn1encodable[]{
            requester,
            requestpolicy,
            dvcs,
            datalocations,
            extensions
        };
        for (int i = 0; i < tags.length; i++)
        {
            int tag = tags[i];
            asn1encodable taggedobject = taggedobjects[i];
            if (taggedobject != null)
            {
                v.add(new dertaggedobject(false, tag, taggedobject));
            }
        }

        return new dersequence(v);
    }

    public string tostring()
    {

        stringbuffer s = new stringbuffer();

        s.append("dvcsrequestinformation {\n");

        if (version != default_version)
        {
            s.append("version: " + version + "\n");
        }
        s.append("service: " + service + "\n");
        if (nonce != null)
        {
            s.append("nonce: " + nonce + "\n");
        }
        if (requesttime != null)
        {
            s.append("requesttime: " + requesttime + "\n");
        }
        if (requester != null)
        {
            s.append("requester: " + requester + "\n");
        }
        if (requestpolicy != null)
        {
            s.append("requestpolicy: " + requestpolicy + "\n");
        }
        if (dvcs != null)
        {
            s.append("dvcs: " + dvcs + "\n");
        }
        if (datalocations != null)
        {
            s.append("datalocations: " + datalocations + "\n");
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

    public servicetype getservice()
    {
        return service;
    }

    public biginteger getnonce()
    {
        return nonce;
    }

    public dvcstime getrequesttime()
    {
        return requesttime;
    }

    public generalnames getrequester()
    {
        return requester;
    }

    public policyinformation getrequestpolicy()
    {
        return requestpolicy;
    }

    public generalnames getdvcs()
    {
        return dvcs;
    }

    public generalnames getdatalocations()
    {
        return datalocations;
    }

    public extensions getextensions()
    {
        return extensions;
    }
}
