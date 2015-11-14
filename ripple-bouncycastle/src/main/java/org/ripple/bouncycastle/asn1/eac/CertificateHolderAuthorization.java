package org.ripple.bouncycastle.asn1.eac;

import java.io.ioexception;
import java.util.hashtable;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1inputstream;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.derapplicationspecific;
import org.ripple.bouncycastle.util.integers;

/**
 * an iso7816certificateholderauthorization structure.
 * <p/>
 * <pre>
 *  certificate holder authorization ::= sequence {
 *      // specifies the format and the rules for the evaluation of the authorization
 *      // level
 *      asn1objectidentifier        oid,
 *      // access rights
 *      derapplicationspecific    accessrights,
 *  }
 * </pre>
 */
public class certificateholderauthorization
    extends asn1object
{
    asn1objectidentifier oid;
    derapplicationspecific accessrights;
    public static final asn1objectidentifier id_role_eac = eacobjectidentifiers.bsi_de.branch("3.1.2.1");
    public static final int cvca = 0xc0;
    public static final int dv_domestic = 0x80;
    public static final int dv_foreign = 0x40;
    public static final int is = 0;
    public static final int radg4 = 0x02;//read access to dg4 (iris)
    public static final int radg3 = 0x01;//read access to dg3 (fingerprint)

    static hashtable rightsdecodemap = new hashtable();
    static bidirectionalmap authorizationrole = new bidirectionalmap();
    static hashtable reversemap = new hashtable();

    static
    {
        rightsdecodemap.put(integers.valueof(radg4), "radg4");
        rightsdecodemap.put(integers.valueof(radg3), "radg3");

        authorizationrole.put(integers.valueof(cvca), "cvca");
        authorizationrole.put(integers.valueof(dv_domestic), "dv_domestic");
        authorizationrole.put(integers.valueof(dv_foreign), "dv_foreign");
        authorizationrole.put(integers.valueof(is), "is");

        /*
          for (int i : rightsdecodemap.keyset())
              reversemap.put(rightsdecodemap.get(i), i);

          for (int i : authorizationrole.keyset())
              reversemap.put(authorizationrole.get(i), i);
          */
    }

    public static string getroledescription(int i)
    {
        return (string)authorizationrole.get(integers.valueof(i));
    }

    public static int getflag(string description)
    {
        integer i = (integer)authorizationrole.getreverse(description);
        if (i == null)
        {
            throw new illegalargumentexception("unknown value " + description);
        }

        return i.intvalue();
    }

    private void setprivatedata(asn1inputstream cha)
        throws ioexception
    {
        asn1primitive obj;
        obj = cha.readobject();
        if (obj instanceof asn1objectidentifier)
        {
            this.oid = (asn1objectidentifier)obj;
        }
        else
        {
            throw new illegalargumentexception("no oid in certicateholderauthorization");
        }
        obj = cha.readobject();
        if (obj instanceof derapplicationspecific)
        {
            this.accessrights = (derapplicationspecific)obj;
        }
        else
        {
            throw new illegalargumentexception("no access rights in certicateholderauthorization");
        }
    }


    /**
     * create an iso7816certificateholderauthorization according to the parameters
     *
     * @param oid    object identifier : specifies the format and the rules for the
     *               evaluatioin of the authorization level.
     * @param rights specifies the access rights
     * @throws ioexception
     */
    public certificateholderauthorization(asn1objectidentifier oid, int rights)
        throws ioexception
    {
        setoid(oid);
        setaccessrights((byte)rights);
    }

    /**
     * create an iso7816certificateholderauthorization according to the {@link derapplicationspecific}
     *
     * @param aspe the derapplicationspecific containing the data
     * @throws ioexception
     */
    public certificateholderauthorization(derapplicationspecific aspe)
        throws ioexception
    {
        if (aspe.getapplicationtag() == eactags.certificate_holder_authorization_template)
        {
            setprivatedata(new asn1inputstream(aspe.getcontents()));
        }
    }

    /**
     * @return containing the access rights
     */
    public int getaccessrights()
    {
        return accessrights.getcontents()[0] & 0xff;
    }

    /**
     * create a derapplicationspecific and set the access rights to "rights"
     *
     * @param rights byte containing the rights.
     */
    private void setaccessrights(byte rights)
    {
        byte[] accessrights = new byte[1];
        accessrights[0] = rights;
        this.accessrights = new derapplicationspecific(
            eactags.gettag(eactags.discretionary_data), accessrights);
    }

    /**
     * @return the object identifier
     */
    public asn1objectidentifier getoid()
    {
        return oid;
    }

    /**
     * set the object identifier
     *
     * @param oid {@link asn1objectidentifier} containing the object identifier
     */
    private void setoid(asn1objectidentifier oid)
    {
        this.oid = oid;
    }

    /**
     * return the certificate holder authorization as a derapplicationspecific object
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        v.add(oid);
        v.add(accessrights);

        return new derapplicationspecific(eactags.certificate_holder_authorization_template, v);
    }
}
