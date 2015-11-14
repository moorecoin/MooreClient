package org.ripple.bouncycastle.asn1.isismtt.x509;

import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1string;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.deria5string;
import org.ripple.bouncycastle.asn1.derobjectidentifier;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.isismtt.isismttobjectidentifiers;
import org.ripple.bouncycastle.asn1.x500.directorystring;

/**
 * names of authorities which are responsible for the administration of title
 * registers.
 * 
 * <pre>
 *             namingauthority ::= sequence 
 *             {
 *               namingauthorityid object identifier optional,
 *               namingauthorityurl ia5string optional,
 *               namingauthoritytext directorystring(size(1..128)) optional
 *             }
 * </pre>
 * @see org.ripple.bouncycastle.asn1.isismtt.x509.admissionsyntax
 * 
 */
public class namingauthority
    extends asn1object
{

    /**
     * profession oids should always be defined under the oid branch of the
     * responsible naming authority. at the time of this writing, the work group
     * 锟絉echt, wirtschaft, steuern锟?(锟絃aw, economy, taxes锟? is registered as the
     * first naming authority under the oid id-isismtt-at-namingauthorities.
     */
    public static final asn1objectidentifier id_isismtt_at_namingauthorities_rechtwirtschaftsteuern =
        new asn1objectidentifier(isismttobjectidentifiers.id_isismtt_at_namingauthorities + ".1");

    private asn1objectidentifier namingauthorityid;
    private string namingauthorityurl;
    private directorystring namingauthoritytext;

    public static namingauthority getinstance(object obj)
    {
        if (obj == null || obj instanceof namingauthority)
        {
            return (namingauthority)obj;
        }

        if (obj instanceof asn1sequence)
        {
            return new namingauthority((asn1sequence)obj);
        }

        throw new illegalargumentexception("illegal object in getinstance: "
            + obj.getclass().getname());
    }

    public static namingauthority getinstance(asn1taggedobject obj, boolean explicit)
    {
        return getinstance(asn1sequence.getinstance(obj, explicit));
    }

    /**
     * constructor from asn1sequence.
     * <p/>
     * <p/>
     * <pre>
     *             namingauthority ::= sequence
     *             {
     *               namingauthorityid object identifier optional,
     *               namingauthorityurl ia5string optional,
     *               namingauthoritytext directorystring(size(1..128)) optional
     *             }
     * </pre>
     *
     * @param seq the asn.1 sequence.
     */
    private namingauthority(asn1sequence seq)
    {

        if (seq.size() > 3)
        {
            throw new illegalargumentexception("bad sequence size: "
                + seq.size());
        }

        enumeration e = seq.getobjects();

        if (e.hasmoreelements())
        {
            asn1encodable o = (asn1encodable)e.nextelement();
            if (o instanceof asn1objectidentifier)
            {
                namingauthorityid = (asn1objectidentifier)o;
            }
            else if (o instanceof deria5string)
            {
                namingauthorityurl = deria5string.getinstance(o).getstring();
            }
            else if (o instanceof asn1string)
            {
                namingauthoritytext = directorystring.getinstance(o);
            }
            else
            {
                throw new illegalargumentexception("bad object encountered: "
                    + o.getclass());
            }
        }
        if (e.hasmoreelements())
        {
            asn1encodable o = (asn1encodable)e.nextelement();
            if (o instanceof deria5string)
            {
                namingauthorityurl = deria5string.getinstance(o).getstring();
            }
            else if (o instanceof asn1string)
            {
                namingauthoritytext = directorystring.getinstance(o);
            }
            else
            {
                throw new illegalargumentexception("bad object encountered: "
                    + o.getclass());
            }
        }
        if (e.hasmoreelements())
        {
            asn1encodable o = (asn1encodable)e.nextelement();
            if (o instanceof asn1string)
            {
                namingauthoritytext = directorystring.getinstance(o);
            }
            else
            {
                throw new illegalargumentexception("bad object encountered: "
                    + o.getclass());
            }

        }
    }

    /**
     * @return returns the namingauthorityid.
     */
    public asn1objectidentifier getnamingauthorityid()
    {
        return namingauthorityid;
    }

    /**
     * @return returns the namingauthoritytext.
     */
    public directorystring getnamingauthoritytext()
    {
        return namingauthoritytext;
    }

    /**
     * @return returns the namingauthorityurl.
     */
    public string getnamingauthorityurl()
    {
        return namingauthorityurl;
    }

        /**
     * constructor from given details.
     * <p/>
     * all parameters can be combined.
     *
     * @param namingauthorityid   objectidentifier for naming authority.
     * @param namingauthorityurl  url for naming authority.
     * @param namingauthoritytext textual representation of naming authority.
         * @deprecated use asn1objectidentifier method
     */
    public namingauthority(derobjectidentifier namingauthorityid,
                           string namingauthorityurl, directorystring namingauthoritytext)
    {
        this.namingauthorityid = new asn1objectidentifier(namingauthorityid.getid());
        this.namingauthorityurl = namingauthorityurl;
        this.namingauthoritytext = namingauthoritytext;
    }

    /**
     * constructor from given details.
     * <p/>
     * all parameters can be combined.
     *
     * @param namingauthorityid   objectidentifier for naming authority.
     * @param namingauthorityurl  url for naming authority.
     * @param namingauthoritytext textual representation of naming authority.
     */
    public namingauthority(asn1objectidentifier namingauthorityid,
                           string namingauthorityurl, directorystring namingauthoritytext)
    {
        this.namingauthorityid = namingauthorityid;
        this.namingauthorityurl = namingauthorityurl;
        this.namingauthoritytext = namingauthoritytext;
    }

    /**
     * produce an object suitable for an asn1outputstream.
     * <p/>
     * returns:
     * <p/>
     * <pre>
     *             namingauthority ::= sequence
     *             {
     *               namingauthorityid object identifier optional,
     *               namingauthorityurl ia5string optional,
     *               namingauthoritytext directorystring(size(1..128)) optional
     *             }
     * </pre>
     *
     * @return a derobject
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector vec = new asn1encodablevector();
        if (namingauthorityid != null)
        {
            vec.add(namingauthorityid);
        }
        if (namingauthorityurl != null)
        {
            vec.add(new deria5string(namingauthorityurl, true));
        }
        if (namingauthoritytext != null)
        {
            vec.add(namingauthoritytext);
        }
        return new dersequence(vec);
    }
}
