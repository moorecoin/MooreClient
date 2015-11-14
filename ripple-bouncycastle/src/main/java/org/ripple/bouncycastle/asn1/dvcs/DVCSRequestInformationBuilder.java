package org.ripple.bouncycastle.asn1.dvcs;

import java.math.biginteger;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;
import org.ripple.bouncycastle.asn1.x509.extensions;
import org.ripple.bouncycastle.asn1.x509.generalname;
import org.ripple.bouncycastle.asn1.x509.generalnames;
import org.ripple.bouncycastle.asn1.x509.policyinformation;
import org.ripple.bouncycastle.util.bigintegers;

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
public class dvcsrequestinformationbuilder
{
    private int version = default_version;

    private final servicetype service;
    private dvcsrequestinformation initialinfo;

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

    public dvcsrequestinformationbuilder(servicetype service)
    {
        this.service = service;
    }

    public dvcsrequestinformationbuilder(dvcsrequestinformation initialinfo)
    {
        this.initialinfo = initialinfo;
        this.service = initialinfo.getservice();
        this.version = initialinfo.getversion();
        this.nonce = initialinfo.getnonce();
        this.requesttime = initialinfo.getrequesttime();
        this.requestpolicy = initialinfo.getrequestpolicy();
        this.dvcs = initialinfo.getdvcs();
        this.datalocations = initialinfo.getdatalocations();
    }

    public dvcsrequestinformation build()
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

        return dvcsrequestinformation.getinstance(new dersequence(v));
    }

    public void setversion(int version)
    {
        if (initialinfo != null)
        {
            throw new illegalstateexception("cannot change version in existing dvcsrequestinformation");
        }

        this.version = version;
    }

    public void setnonce(biginteger nonce)
    {
        // rfc 3029, 9.1: the dvcs may modify the fields
        // 'dvcs', 'requester', 'datalocations', and 'nonce' of the reqinfo structure

        // rfc 3029, 9.1: the only modification
        // allowed to a 'nonce' is the inclusion of a new field if it was not
        // present, or to concatenate other data to the end (right) of an
        // existing value.
        if (initialinfo != null)
        {
            if (initialinfo.getnonce() == null)
            {
                this.nonce = nonce;
            }
            else
            {
                byte[] initialbytes = initialinfo.getnonce().tobytearray();
                byte[] newbytes = bigintegers.asunsignedbytearray(nonce);
                byte[] noncebytes = new byte[initialbytes.length + newbytes.length];

                system.arraycopy(initialbytes, 0, noncebytes, 0, initialbytes.length);
                system.arraycopy(newbytes, 0, noncebytes, initialbytes.length, newbytes.length);

                this.nonce = new biginteger(noncebytes);
            }
        }

        this.nonce = nonce;
    }

    public void setrequesttime(dvcstime requesttime)
    {
        if (initialinfo != null)
        {
            throw new illegalstateexception("cannot change request time in existing dvcsrequestinformation");
        }

        this.requesttime = requesttime;
    }

    public void setrequester(generalname requester)
    {
        this.setrequester(new generalnames(requester));
    }

    public void setrequester(generalnames requester)
    {
        // rfc 3029, 9.1: the dvcs may modify the fields
        // 'dvcs', 'requester', 'datalocations', and 'nonce' of the reqinfo structure

        this.requester = requester;
    }

    public void setrequestpolicy(policyinformation requestpolicy)
    {
        if (initialinfo != null)
        {
            throw new illegalstateexception("cannot change request policy in existing dvcsrequestinformation");
        }

        this.requestpolicy = requestpolicy;
    }

    public void setdvcs(generalname dvcs)
    {
        this.setdvcs(new generalnames(dvcs));
    }

    public void setdvcs(generalnames dvcs)
    {
        // rfc 3029, 9.1: the dvcs may modify the fields
        // 'dvcs', 'requester', 'datalocations', and 'nonce' of the reqinfo structure

        this.dvcs = dvcs;
    }

    public void setdatalocations(generalname datalocation)
    {
        this.setdatalocations(new generalnames(datalocation));
    }

    public void setdatalocations(generalnames datalocations)
    {
        // rfc 3029, 9.1: the dvcs may modify the fields
        // 'dvcs', 'requester', 'datalocations', and 'nonce' of the reqinfo structure

        this.datalocations = datalocations;
    }

    public void setextensions(extensions extensions)
    {
        if (initialinfo != null)
        {
            throw new illegalstateexception("cannot change extensions in existing dvcsrequestinformation");
        }

        this.extensions = extensions;
    }
}
