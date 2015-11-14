package org.ripple.bouncycastle.asn1.cmp;

import org.ripple.bouncycastle.asn1.asn1choice;
import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dertaggedobject;
import org.ripple.bouncycastle.asn1.crmf.certreqmessages;
import org.ripple.bouncycastle.asn1.pkcs.certificationrequest;

public class pkibody
    extends asn1object
    implements asn1choice
{
    public static final int type_init_req = 0;
    public static final int type_init_rep = 1;
    public static final int type_cert_req = 2;
    public static final int type_cert_rep = 3;
    public static final int type_p10_cert_req = 4;
    public static final int type_popo_chall = 5;
    public static final int type_popo_rep = 6;
    public static final int type_key_update_req = 7;
    public static final int type_key_update_rep = 8;
    public static final int type_key_recovery_req = 9;
    public static final int type_key_recovery_rep = 10;
    public static final int type_revocation_req = 11;
    public static final int type_revocation_rep = 12;
    public static final int type_cross_cert_req = 13;
    public static final int type_cross_cert_rep = 14;
    public static final int type_ca_key_update_ann = 15;
    public static final int type_cert_ann = 16;
    public static final int type_revocation_ann = 17;
    public static final int type_crl_ann = 18;
    public static final int type_confirm = 19;
    public static final int type_nested = 20;
    public static final int type_gen_msg = 21;
    public static final int type_gen_rep = 22;
    public static final int type_error = 23;
    public static final int type_cert_confirm = 24;
    public static final int type_poll_req = 25;
    public static final int type_poll_rep = 26;

    private int tagno;
    private asn1encodable body;

    public static pkibody getinstance(object o)
    {
        if (o == null || o instanceof pkibody)
        {
            return (pkibody)o;
        }

        if (o instanceof asn1taggedobject)
        {
            return new pkibody((asn1taggedobject)o);
        }

        throw new illegalargumentexception("invalid object: " + o.getclass().getname());
    }

    private pkibody(asn1taggedobject tagged)
    {
        tagno = tagged.gettagno();
        body = getbodyfortype(tagno, tagged.getobject());
    }

    /**
     * creates a new pkibody.
     * @param type one of the type_* constants
     * @param content message content
     */
    public pkibody(
        int type,
        asn1encodable content)
    {
        tagno = type;
        body = getbodyfortype(type, content);
    }

    private static asn1encodable getbodyfortype(
        int type,
        asn1encodable o)
    {
        switch (type)
        {
        case type_init_req:
            return certreqmessages.getinstance(o);
        case type_init_rep:
            return certrepmessage.getinstance(o);
        case type_cert_req:
            return certreqmessages.getinstance(o);
        case type_cert_rep:
            return certrepmessage.getinstance(o);
        case type_p10_cert_req:
            return certificationrequest.getinstance(o);
        case type_popo_chall:
            return popodeckeychallcontent.getinstance(o);
        case type_popo_rep:
            return popodeckeyrespcontent.getinstance(o);
        case type_key_update_req:
            return certreqmessages.getinstance(o);
        case type_key_update_rep:
            return certrepmessage.getinstance(o);
        case type_key_recovery_req:
            return certreqmessages.getinstance(o);
        case type_key_recovery_rep:
            return keyrecrepcontent.getinstance(o);
        case type_revocation_req:
            return revreqcontent.getinstance(o);
        case type_revocation_rep:
            return revrepcontent.getinstance(o);
        case type_cross_cert_req:
            return certreqmessages.getinstance(o);
        case type_cross_cert_rep:
            return certrepmessage.getinstance(o);
        case type_ca_key_update_ann:
            return cakeyupdanncontent.getinstance(o);
        case type_cert_ann:
            return cmpcertificate.getinstance(o);
        case type_revocation_ann:
            return revanncontent.getinstance(o);
        case type_crl_ann:
            return crlanncontent.getinstance(o);
        case type_confirm:
            return pkiconfirmcontent.getinstance(o);
        case type_nested:
            return pkimessages.getinstance(o);
        case type_gen_msg:
            return genmsgcontent.getinstance(o);
        case type_gen_rep:
            return genrepcontent.getinstance(o);
        case type_error:
            return errormsgcontent.getinstance(o);
        case type_cert_confirm:
            return certconfirmcontent.getinstance(o);
        case type_poll_req:
            return pollreqcontent.getinstance(o);
        case type_poll_rep:
            return pollrepcontent.getinstance(o);
        default:
            throw new illegalargumentexception("unknown tag number: " + type);
        }
    }

    public int gettype()
    {
        return tagno;
    }

    public asn1encodable getcontent()
    {
        return body;
    }

    /**
     * <pre>
     * pkibody ::= choice {       -- message-specific body elements
     *        ir       [0]  certreqmessages,        --initialization request
     *        ip       [1]  certrepmessage,         --initialization response
     *        cr       [2]  certreqmessages,        --certification request
     *        cp       [3]  certrepmessage,         --certification response
     *        p10cr    [4]  certificationrequest,   --imported from [pkcs10]
     *        popdecc  [5]  popodeckeychallcontent, --pop challenge
     *        popdecr  [6]  popodeckeyrespcontent,  --pop response
     *        kur      [7]  certreqmessages,        --key update request
     *        kup      [8]  certrepmessage,         --key update response
     *        krr      [9]  certreqmessages,        --key recovery request
     *        krp      [10] keyrecrepcontent,       --key recovery response
     *        rr       [11] revreqcontent,          --revocation request
     *        rp       [12] revrepcontent,          --revocation response
     *        ccr      [13] certreqmessages,        --cross-cert. request
     *        ccp      [14] certrepmessage,         --cross-cert. response
     *        ckuann   [15] cakeyupdanncontent,     --ca key update ann.
     *        cann     [16] certanncontent,         --certificate ann.
     *        rann     [17] revanncontent,          --revocation ann.
     *        crlann   [18] crlanncontent,          --crl announcement
     *        pkiconf  [19] pkiconfirmcontent,      --confirmation
     *        nested   [20] nestedmessagecontent,   --nested message
     *        genm     [21] genmsgcontent,          --general message
     *        genp     [22] genrepcontent,          --general response
     *        error    [23] errormsgcontent,        --error message
     *        certconf [24] certconfirmcontent,     --certificate confirm
     *        pollreq  [25] pollreqcontent,         --polling request
     *        pollrep  [26] pollrepcontent          --polling response
     * }
     * </pre>
     * @return a basic asn.1 object representation.
     */
    public asn1primitive toasn1primitive()
    {
        return new dertaggedobject(true, tagno, body);
    }
}
