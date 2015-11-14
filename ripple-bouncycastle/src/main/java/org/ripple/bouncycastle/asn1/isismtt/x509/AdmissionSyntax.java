package org.ripple.bouncycastle.asn1.isismtt.x509;

import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.x509.generalname;

/**
 * attribute to indicate admissions to certain professions.
 * <p/>
 * <pre>
 *     admissionsyntax ::= sequence
 *     {
 *       admissionauthority generalname optional,
 *       contentsofadmissions sequence of admissions
 *     }
 * <p/>
 *     admissions ::= sequence
 *     {
 *       admissionauthority [0] explicit generalname optional
 *       namingauthority [1] explicit namingauthority optional
 *       professioninfos sequence of professioninfo
 *     }
 * <p/>
 *     namingauthority ::= sequence
 *     {
 *       namingauthorityid object identifier optional,
 *       namingauthorityurl ia5string optional,
 *       namingauthoritytext directorystring(size(1..128)) optional
 *     }
 * <p/>
 *     professioninfo ::= sequence
 *     {
 *       namingauthority [0] explicit namingauthority optional,
 *       professionitems sequence of directorystring (size(1..128)),
 *       professionoids sequence of object identifier optional,
 *       registrationnumber printablestring(size(1..128)) optional,
 *       addprofessioninfo octet string optional
 *     }
 * </pre>
 * <p/>
 * <p/>
 * isis-mtt profile: the relatively complex structure of admissionsyntax
 * supports the following concepts and requirements:
 * <ul>
 * <li> external institutions (e.g. professional associations, chambers, unions,
 * administrative bodies, companies, etc.), which are responsible for granting
 * and verifying professional admissions, are indicated by means of the data
 * field admissionauthority. an admission authority is indicated by a
 * generalname object. here an x.501 directory name (distinguished name) can be
 * indicated in the field directoryname, a url address can be indicated in the
 * field uniformresourceidentifier, and an object identifier can be indicated in
 * the field registeredid.
 * <li> the names of authorities which are responsible for the administration of
 * title registers are indicated in the data field namingauthority. the name of
 * the authority can be identified by an object identifier in the field
 * namingauthorityid, by means of a text string in the field
 * namingauthoritytext, by means of a url address in the field
 * namingauthorityurl, or by a combination of them. for example, the text string
 * can contain the name of the authority, the country and the name of the title
 * register. the url-option refers to a web page which contains lists with
 * 锟給fficially锟?registered professions (text and possibly oid) as well as
 * further information on these professions. object identifiers for the
 * component namingauthorityid are grouped under the oid-branch
 * id-isis-at-namingauthorities and must be applied for.
 * <li>see
 * http://www.teletrust.de/anwend.asp?id=30200&sprache=e_&homepg=0 for
 * an application form and http://www.teletrust.de/links.asp?id=30220,11
 * for an overview of registered naming authorities.
 * <li> by means of the data type professioninfo certain professions,
 * specializations, disciplines, fields of activity, etc. are identified. a
 * profession is represented by one or more text strings, resp. profession oids
 * in the fields professionitems and professionoids and by a registration number
 * in the field registrationnumber. an indication in text form must always be
 * present, whereas the other indications are optional. the component
 * addprofessioninfo may contain additional applicationspecific information in
 * der-encoded form.
 * </ul>
 * <p/>
 * by means of different namingauthority-oids or profession oids hierarchies of
 * professions, specializations, disciplines, fields of activity, etc. can be
 * expressed. the issuing admission authority should always be indicated (field
 * admissionauthority), whenever a registration number is presented. still,
 * information on admissions can be given without indicating an admission or a
 * naming authority by the exclusive use of the component professionitems. in
 * this case the certification authority is responsible for the verification of
 * the admission information.
 * <p/>
 * <p/>
 * <p/>
 * this attribute is single-valued. still, several admissions can be captured in
 * the sequence structure of the component contentsofadmissions of
 * admissionsyntax or in the component professioninfos of admissions. the
 * component admissionauthority of admissionsyntax serves as default value for
 * the component admissionauthority of admissions. within the latter component
 * the default value can be overwritten, in case that another authority is
 * responsible. the component namingauthority of admissions serves as a default
 * value for the component namingauthority of professioninfo. within the latter
 * component the default value can be overwritten, in case that another naming
 * authority needs to be recorded.
 * <p/>
 * the length of the string objects is limited to 128 characters. it is
 * recommended to indicate a namingauthorityurl in all issued attribute
 * certificates. if a namingauthorityurl is indicated, the field professionitems
 * of professioninfo should contain only registered titles. if the field
 * professionoids exists, it has to contain the oids of the professions listed
 * in professionitems in the same order. in general, the field professioninfos
 * should contain only one entry, unless the admissions that are to be listed
 * are logically connected (e.g. they have been issued under the same admission
 * number).
 *
 * @see org.ripple.bouncycastle.asn1.isismtt.x509.admissions
 * @see org.ripple.bouncycastle.asn1.isismtt.x509.professioninfo
 * @see org.ripple.bouncycastle.asn1.isismtt.x509.namingauthority
 */
public class admissionsyntax
    extends asn1object
{

    private generalname admissionauthority;

    private asn1sequence contentsofadmissions;

    public static admissionsyntax getinstance(object obj)
    {
        if (obj == null || obj instanceof admissionsyntax)
        {
            return (admissionsyntax)obj;
        }

        if (obj instanceof asn1sequence)
        {
            return new admissionsyntax((asn1sequence)obj);
        }

        throw new illegalargumentexception("illegal object in getinstance: "
            + obj.getclass().getname());
    }

    /**
     * constructor from asn1sequence.
     * <p/>
     * the sequence is of type procurationsyntax:
     * <p/>
     * <pre>
     *     admissionsyntax ::= sequence
     *     {
     *       admissionauthority generalname optional,
     *       contentsofadmissions sequence of admissions
     *     }
     * <p/>
     *     admissions ::= sequence
     *     {
     *       admissionauthority [0] explicit generalname optional
     *       namingauthority [1] explicit namingauthority optional
     *       professioninfos sequence of professioninfo
     *     }
     * <p/>
     *     namingauthority ::= sequence
     *     {
     *       namingauthorityid object identifier optional,
     *       namingauthorityurl ia5string optional,
     *       namingauthoritytext directorystring(size(1..128)) optional
     *     }
     * <p/>
     *     professioninfo ::= sequence
     *     {
     *       namingauthority [0] explicit namingauthority optional,
     *       professionitems sequence of directorystring (size(1..128)),
     *       professionoids sequence of object identifier optional,
     *       registrationnumber printablestring(size(1..128)) optional,
     *       addprofessioninfo octet string optional
     *     }
     * </pre>
     *
     * @param seq the asn.1 sequence.
     */
    private admissionsyntax(asn1sequence seq)
    {
        switch (seq.size())
        {
        case 1:
            contentsofadmissions = dersequence.getinstance(seq.getobjectat(0));
            break;
        case 2:
            admissionauthority = generalname.getinstance(seq.getobjectat(0));
            contentsofadmissions = dersequence.getinstance(seq.getobjectat(1));
            break;
        default:
            throw new illegalargumentexception("bad sequence size: " + seq.size());
        }
    }

    /**
     * constructor from given details.
     *
     * @param admissionauthority   the admission authority.
     * @param contentsofadmissions the admissions.
     */
    public admissionsyntax(generalname admissionauthority, asn1sequence contentsofadmissions)
    {
        this.admissionauthority = admissionauthority;
        this.contentsofadmissions = contentsofadmissions;
    }

    /**
     * produce an object suitable for an asn1outputstream.
     * <p/>
     * returns:
     * <p/>
     * <pre>
     *     admissionsyntax ::= sequence
     *     {
     *       admissionauthority generalname optional,
     *       contentsofadmissions sequence of admissions
     *     }
     * <p/>
     *     admissions ::= sequence
     *     {
     *       admissionauthority [0] explicit generalname optional
     *       namingauthority [1] explicit namingauthority optional
     *       professioninfos sequence of professioninfo
     *     }
     * <p/>
     *     namingauthority ::= sequence
     *     {
     *       namingauthorityid object identifier optional,
     *       namingauthorityurl ia5string optional,
     *       namingauthoritytext directorystring(size(1..128)) optional
     *     }
     * <p/>
     *     professioninfo ::= sequence
     *     {
     *       namingauthority [0] explicit namingauthority optional,
     *       professionitems sequence of directorystring (size(1..128)),
     *       professionoids sequence of object identifier optional,
     *       registrationnumber printablestring(size(1..128)) optional,
     *       addprofessioninfo octet string optional
     *     }
     * </pre>
     *
     * @return a derobject
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector vec = new asn1encodablevector();
        if (admissionauthority != null)
        {
            vec.add(admissionauthority);
        }
        vec.add(contentsofadmissions);
        return new dersequence(vec);
    }

    /**
     * @return returns the admissionauthority if present, null otherwise.
     */
    public generalname getadmissionauthority()
    {
        return admissionauthority;
    }

    /**
     * @return returns the contentsofadmissions.
     */
    public admissions[] getcontentsofadmissions()
    {
        admissions[] admissions = new admissions[contentsofadmissions.size()];
        int count = 0;
        for (enumeration e = contentsofadmissions.getobjects(); e.hasmoreelements();)
        {
            admissions[count++] = admissions.getinstance(e.nextelement());
        }
        return admissions;
    }
}
