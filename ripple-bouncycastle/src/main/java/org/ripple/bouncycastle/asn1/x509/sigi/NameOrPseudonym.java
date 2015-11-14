package org.ripple.bouncycastle.asn1.x509.sigi;

import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1choice;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1string;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.x500.directorystring;

/**
 * structure for a name or pseudonym.
 * 
 * <pre>
 *       nameorpseudonym ::= choice {
 *            surandgivenname sequence {
 *              surname directorystring,
 *              givenname sequence of directorystring 
 *         },
 *            pseudonym directorystring 
 *       }
 * </pre>
 * 
 * @see org.ripple.bouncycastle.asn1.x509.sigi.personaldata
 * 
 */
public class nameorpseudonym
    extends asn1object
    implements asn1choice
{
    private directorystring pseudonym;

    private directorystring surname;

    private asn1sequence givenname;

    public static nameorpseudonym getinstance(object obj)
    {
        if (obj == null || obj instanceof nameorpseudonym)
        {
            return (nameorpseudonym)obj;
        }

        if (obj instanceof asn1string)
        {
            return new nameorpseudonym(directorystring.getinstance(obj));
        }

        if (obj instanceof asn1sequence)
        {
            return new nameorpseudonym((asn1sequence)obj);
        }

        throw new illegalargumentexception("illegal object in getinstance: "
            + obj.getclass().getname());
    }

    /**
     * constructor from directorystring.
     * <p/>
     * the sequence is of type nameorpseudonym:
     * <p/>
     * <pre>
     *       nameorpseudonym ::= choice {
     *            surandgivenname sequence {
     *              surname directorystring,
     *              givenname sequence of directorystring
     *         },
     *            pseudonym directorystring
     *       }
     * </pre>
     * @param pseudonym pseudonym value to use.
     */
    public nameorpseudonym(directorystring pseudonym)
    {
        this.pseudonym = pseudonym;
    }

    /**
     * constructor from asn1sequence.
     * <p/>
     * the sequence is of type nameorpseudonym:
     * <p/>
     * <pre>
     *       nameorpseudonym ::= choice {
     *            surandgivenname sequence {
     *              surname directorystring,
     *              givenname sequence of directorystring
     *         },
     *            pseudonym directorystring
     *       }
     * </pre>
     *
     * @param seq the asn.1 sequence.
     */
    private nameorpseudonym(asn1sequence seq)
    {
        if (seq.size() != 2)
        {
            throw new illegalargumentexception("bad sequence size: "
                + seq.size());
        }

        if (!(seq.getobjectat(0) instanceof asn1string))
        {
            throw new illegalargumentexception("bad object encountered: "
                + seq.getobjectat(0).getclass());
        }

        surname = directorystring.getinstance(seq.getobjectat(0));
        givenname = asn1sequence.getinstance(seq.getobjectat(1));
    }

    /**
     * constructor from a given details.
     *
     * @param pseudonym the pseudonym.
     */
    public nameorpseudonym(string pseudonym)
    {
        this(new directorystring(pseudonym));
    }

    /**
     * constructor from a given details.
     *
     * @param surname   the surname.
     * @param givenname a sequence of directory strings making up the givenname
     */
    public nameorpseudonym(directorystring surname, asn1sequence givenname)
    {
        this.surname = surname;
        this.givenname = givenname;
    }

    public directorystring getpseudonym()
    {
        return pseudonym;
    }

    public directorystring getsurname()
    {
        return surname;
    }

    public directorystring[] getgivenname()
    {
        directorystring[] items = new directorystring[givenname.size()];
        int count = 0;
        for (enumeration e = givenname.getobjects(); e.hasmoreelements();)
        {
            items[count++] = directorystring.getinstance(e.nextelement());
        }
        return items;
    }

    /**
     * produce an object suitable for an asn1outputstream.
     * <p/>
     * returns:
     * <p/>
     * <pre>
     *       nameorpseudonym ::= choice {
     *            surandgivenname sequence {
     *              surname directorystring,
     *              givenname sequence of directorystring
     *         },
     *            pseudonym directorystring
     *       }
     * </pre>
     *
     * @return a derobject
     */
    public asn1primitive toasn1primitive()
    {
        if (pseudonym != null)
        {
            return pseudonym.toasn1primitive();
        }
        else
        {
            asn1encodablevector vec1 = new asn1encodablevector();
            vec1.add(surname);
            vec1.add(givenname);
            return new dersequence(vec1);
        }
    }
}
