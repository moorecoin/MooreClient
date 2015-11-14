package org.ripple.bouncycastle.asn1.cmp;

import java.math.biginteger;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.derbitstring;
import org.ripple.bouncycastle.asn1.dersequence;

public class pkistatusinfo
    extends asn1object
{
    asn1integer      status;
    pkifreetext     statusstring;
    derbitstring    failinfo;

    public static pkistatusinfo getinstance(
        asn1taggedobject obj,
        boolean explicit)
    {
        return getinstance(asn1sequence.getinstance(obj, explicit));
    }

    public static pkistatusinfo getinstance(
        object obj)
    {
        if (obj instanceof pkistatusinfo)
        {
            return (pkistatusinfo)obj;
        }
        else if (obj != null)
        {
            return new pkistatusinfo(asn1sequence.getinstance(obj));
        }

        return null;
    }

    private pkistatusinfo(
        asn1sequence seq)
    {
        this.status = asn1integer.getinstance(seq.getobjectat(0));

        this.statusstring = null;
        this.failinfo = null;

        if (seq.size() > 2)
        {
            this.statusstring = pkifreetext.getinstance(seq.getobjectat(1));
            this.failinfo = derbitstring.getinstance(seq.getobjectat(2));
        }
        else if (seq.size() > 1)
        {
            object obj = seq.getobjectat(1); 
            if (obj instanceof derbitstring)
            {
                this.failinfo = derbitstring.getinstance(obj);
            }
            else
            {
                this.statusstring = pkifreetext.getinstance(obj);
            }
        }
    }

    /**
     * @param status
     */
    public pkistatusinfo(pkistatus status)
    {
        this.status = asn1integer.getinstance(status.toasn1primitive());
    }

    /**
     *
     * @param status
     * @param statusstring
     */
    public pkistatusinfo(
        pkistatus   status,
        pkifreetext statusstring)
    {
        this.status = asn1integer.getinstance(status.toasn1primitive());
        this.statusstring = statusstring;
    }

    public pkistatusinfo(
        pkistatus      status,
        pkifreetext    statusstring,
        pkifailureinfo failinfo)
    {
        this.status = asn1integer.getinstance(status.toasn1primitive());
        this.statusstring = statusstring;
        this.failinfo = failinfo;
    }
    
    public biginteger getstatus()
    {
        return status.getvalue();
    }

    public pkifreetext getstatusstring()
    {
        return statusstring;
    }

    public derbitstring getfailinfo()
    {
        return failinfo;
    }

    /**
     * <pre>
     * pkistatusinfo ::= sequence {
     *     status        pkistatus,                (integer)
     *     statusstring  pkifreetext     optional,
     *     failinfo      pkifailureinfo  optional  (bit string)
     * }
     *
     * pkistatus:
     *   granted                (0), -- you got exactly what you asked for
     *   grantedwithmods        (1), -- you got something like what you asked for
     *   rejection              (2), -- you don't get it, more information elsewhere in the message
     *   waiting                (3), -- the request body part has not yet been processed, expect to hear more later
     *   revocationwarning      (4), -- this message contains a warning that a revocation is imminent
     *   revocationnotification (5), -- notification that a revocation has occurred
     *   keyupdatewarning       (6)  -- update already done for the oldcertid specified in certreqmsg
     *
     * pkifailureinfo:
     *   badalg           (0), -- unrecognized or unsupported algorithm identifier
     *   badmessagecheck  (1), -- integrity check failed (e.g., signature did not verify)
     *   badrequest       (2), -- transaction not permitted or supported
     *   badtime          (3), -- messagetime was not sufficiently close to the system time, as defined by local policy
     *   badcertid        (4), -- no certificate could be found matching the provided criteria
     *   baddataformat    (5), -- the data submitted has the wrong format
     *   wrongauthority   (6), -- the authority indicated in the request is different from the one creating the response token
     *   incorrectdata    (7), -- the requester's data is incorrect (for notary services)
     *   missingtimestamp (8), -- when the timestamp is missing but should be there (by policy)
     *   badpop           (9)  -- the proof-of-possession failed
     *
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector  v = new asn1encodablevector();

        v.add(status);

        if (statusstring != null)
        {
            v.add(statusstring);
        }

        if (failinfo!= null)
        {
            v.add(failinfo);
        }

        return new dersequence(v);
    }
}
