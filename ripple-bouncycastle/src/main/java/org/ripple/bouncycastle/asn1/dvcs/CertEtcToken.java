package org.ripple.bouncycastle.asn1.dvcs;

import org.ripple.bouncycastle.asn1.asn1choice;
import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dertaggedobject;
import org.ripple.bouncycastle.asn1.cmp.pkistatusinfo;
import org.ripple.bouncycastle.asn1.cms.contentinfo;
import org.ripple.bouncycastle.asn1.ess.esscertid;
import org.ripple.bouncycastle.asn1.ocsp.certid;
import org.ripple.bouncycastle.asn1.ocsp.certstatus;
import org.ripple.bouncycastle.asn1.ocsp.ocspresponse;
import org.ripple.bouncycastle.asn1.smime.smimecapabilities;
import org.ripple.bouncycastle.asn1.x509.certificate;
import org.ripple.bouncycastle.asn1.x509.certificatelist;
import org.ripple.bouncycastle.asn1.x509.extension;

/**
 * <pre>
 * certetctoken ::= choice {
 *         certificate                  [0] implicit certificate ,
 *         esscertid                    [1] esscertid ,
 *         pkistatus                    [2] implicit pkistatusinfo ,
 *         assertion                    [3] contentinfo ,
 *         crl                          [4] implicit certificatelist,
 *         ocspcertstatus               [5] certstatus,
 *         oscpcertid                   [6] implicit certid ,
 *         oscpresponse                 [7] implicit ocspresponse,
 *         capabilities                 [8] smimecapabilities,
 *         extension                    extension
 * }
 * </pre>
 */
public class certetctoken
    extends asn1object
    implements asn1choice
{
    public static final int tag_certificate = 0;
    public static final int tag_esscertid = 1;
    public static final int tag_pkistatus = 2;
    public static final int tag_assertion = 3;
    public static final int tag_crl = 4;
    public static final int tag_ocspcertstatus = 5;
    public static final int tag_ocspcertid = 6;
    public static final int tag_ocspresponse = 7;
    public static final int tag_capabilities = 8;

    private static final boolean[] explicit = new boolean[]
        {
            false, true, false, true, false, true, false, false, true
        };

    private int tagno;
    private asn1encodable value;
    private extension extension;

    public certetctoken(int tagno, asn1encodable value)
    {
        this.tagno = tagno;
        this.value = value;
    }

    public certetctoken(extension extension)
    {
        this.tagno = -1;
        this.extension = extension;
    }

    private certetctoken(asn1taggedobject choice)
    {
        this.tagno = choice.gettagno();

        switch (tagno)
        {
        case tag_certificate:
            value = certificate.getinstance(choice, false);
            break;
        case tag_esscertid:
            value = esscertid.getinstance(choice.getobject());
            break;
        case tag_pkistatus:
            value = pkistatusinfo.getinstance(choice, false);
            break;
        case tag_assertion:
            value = contentinfo.getinstance(choice.getobject());
            break;
        case tag_crl:
            value = certificatelist.getinstance(choice, false);
            break;
        case tag_ocspcertstatus:
            value = certstatus.getinstance(choice.getobject());
            break;
        case tag_ocspcertid:
            value = certid.getinstance(choice, false);
            break;
        case tag_ocspresponse:
            value = ocspresponse.getinstance(choice, false);
            break;
        case tag_capabilities:
            value = smimecapabilities.getinstance(choice.getobject());
            break;
        default:
            throw new illegalargumentexception("unknown tag: " + tagno);
        }
    }

    public static certetctoken getinstance(object obj)
    {
        if (obj instanceof certetctoken)
        {
            return (certetctoken)obj;
        }
        else if (obj instanceof asn1taggedobject)
        {
            return new certetctoken((asn1taggedobject)obj);
        }
        else if (obj != null)
        {
            return new certetctoken(extension.getinstance(obj));
        }

        return null;
    }

    public asn1primitive toasn1primitive()
    {
        if (extension == null)
        {
            return new dertaggedobject(explicit[tagno], tagno, value);
        }
        else
        {
            return extension.toasn1primitive();
        }
    }

    public int gettagno()
    {
        return tagno;
    }

    public asn1encodable getvalue()
    {
        return value;
    }

    public extension getextension()
    {
        return extension;
    }

    public string tostring()
    {
        return "certetctoken {\n" + value + "}\n";
    }

    public static certetctoken[] arrayfromsequence(asn1sequence seq)
    {
        certetctoken[] tmp = new certetctoken[seq.size()];

        for (int i = 0; i != tmp.length; i++)
        {
            tmp[i] = certetctoken.getinstance(seq.getobjectat(i));
        }

        return tmp;
    }
}
