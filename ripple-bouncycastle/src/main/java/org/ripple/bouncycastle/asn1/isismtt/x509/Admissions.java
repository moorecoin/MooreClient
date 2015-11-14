package org.ripple.bouncycastle.asn1.isismtt.x509;

import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;
import org.ripple.bouncycastle.asn1.x509.generalname;

/**
 * an admissions structure.
 * <p/>
 * <pre>
 *            admissions ::= sequence
 *            {
 *              admissionauthority [0] explicit generalname optional
 *              namingauthority [1] explicit namingauthority optional
 *              professioninfos sequence of professioninfo
 *            }
 * <p/>
 * </pre>
 *
 * @see org.ripple.bouncycastle.asn1.isismtt.x509.admissionsyntax
 * @see org.ripple.bouncycastle.asn1.isismtt.x509.professioninfo
 * @see org.ripple.bouncycastle.asn1.isismtt.x509.namingauthority
 */
public class admissions 
    extends asn1object
{

    private generalname admissionauthority;

    private namingauthority namingauthority;

    private asn1sequence professioninfos;

    public static admissions getinstance(object obj)
    {
        if (obj == null || obj instanceof admissions)
        {
            return (admissions)obj;
        }

        if (obj instanceof asn1sequence)
        {
            return new admissions((asn1sequence)obj);
        }

        throw new illegalargumentexception("illegal object in getinstance: " + obj.getclass().getname());
    }

    /**
     * constructor from asn1sequence.
     * <p/>
     * the sequence is of type procurationsyntax:
     * <p/>
     * <pre>
     *            admissions ::= sequence
     *            {
     *              admissionauthority [0] explicit generalname optional
     *              namingauthority [1] explicit namingauthority optional
     *              professioninfos sequence of professioninfo
     *            }
     * </pre>
     *
     * @param seq the asn.1 sequence.
     */
    private admissions(asn1sequence seq)
    {
        if (seq.size() > 3)
        {
            throw new illegalargumentexception("bad sequence size: "
                + seq.size());
        }
        enumeration e = seq.getobjects();

        asn1encodable o = (asn1encodable)e.nextelement();
        if (o instanceof asn1taggedobject)
        {
            switch (((asn1taggedobject)o).gettagno())
            {
            case 0:
                admissionauthority = generalname.getinstance((asn1taggedobject)o, true);
                break;
            case 1:
                namingauthority = namingauthority.getinstance((asn1taggedobject)o, true);
                break;
            default:
                throw new illegalargumentexception("bad tag number: " + ((asn1taggedobject)o).gettagno());
            }
            o = (asn1encodable)e.nextelement();
        }
        if (o instanceof asn1taggedobject)
        {
            switch (((asn1taggedobject)o).gettagno())
            {
            case 1:
                namingauthority = namingauthority.getinstance((asn1taggedobject)o, true);
                break;
            default:
                throw new illegalargumentexception("bad tag number: " + ((asn1taggedobject)o).gettagno());
            }
            o = (asn1encodable)e.nextelement();
        }
        professioninfos = asn1sequence.getinstance(o);
        if (e.hasmoreelements())
        {
            throw new illegalargumentexception("bad object encountered: "
                + e.nextelement().getclass());
        }
    }

    /**
     * constructor from a given details.
     * <p/>
     * parameter <code>professioninfos</code> is mandatory.
     *
     * @param admissionauthority the admission authority.
     * @param namingauthority    the naming authority.
     * @param professioninfos    the profession infos.
     */
    public admissions(generalname admissionauthority,
                      namingauthority namingauthority, professioninfo[] professioninfos)
    {
        this.admissionauthority = admissionauthority;
        this.namingauthority = namingauthority;
        this.professioninfos = new dersequence(professioninfos);
    }

    public generalname getadmissionauthority()
    {
        return admissionauthority;
    }

    public namingauthority getnamingauthority()
    {
        return namingauthority;
    }

    public professioninfo[] getprofessioninfos()
    {
        professioninfo[] infos = new professioninfo[professioninfos.size()];
        int count = 0;
        for (enumeration e = professioninfos.getobjects(); e.hasmoreelements();)
        {
            infos[count++] = professioninfo.getinstance(e.nextelement());
        }
        return infos;
    }

    /**
     * produce an object suitable for an asn1outputstream.
     * <p/>
     * returns:
     * <p/>
     * <pre>
     *       admissions ::= sequence
     *       {
     *         admissionauthority [0] explicit generalname optional
     *         namingauthority [1] explicit namingauthority optional
     *         professioninfos sequence of professioninfo
     *       }
     * <p/>
     * </pre>
     *
     * @return an asn1primitive
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector vec = new asn1encodablevector();
        
        if (admissionauthority != null)
        {
            vec.add(new dertaggedobject(true, 0, admissionauthority));
        }
        if (namingauthority != null)
        {
            vec.add(new dertaggedobject(true, 1, namingauthority));
        }
        vec.add(professioninfos);

        return new dersequence(vec);
    }
}
