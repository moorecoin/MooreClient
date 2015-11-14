package org.ripple.bouncycastle.x509;

import java.io.ioexception;
import java.math.biginteger;
import java.security.messagedigest;
import java.security.principal;
import java.security.cert.certselector;
import java.security.cert.certificate;
import java.security.cert.certificateencodingexception;
import java.security.cert.certificateparsingexception;
import java.security.cert.x509certificate;
import java.util.arraylist;
import java.util.list;

import javax.security.auth.x500.x500principal;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;
import org.ripple.bouncycastle.asn1.x509.generalname;
import org.ripple.bouncycastle.asn1.x509.generalnames;
import org.ripple.bouncycastle.asn1.x509.holder;
import org.ripple.bouncycastle.asn1.x509.issuerserial;
import org.ripple.bouncycastle.asn1.x509.objectdigestinfo;
import org.ripple.bouncycastle.jce.principalutil;
import org.ripple.bouncycastle.jce.x509principal;
import org.ripple.bouncycastle.util.arrays;
import org.ripple.bouncycastle.util.selector;

/**
 * the holder object.
 * 
 * <pre>
 *          holder ::= sequence {
 *                basecertificateid   [0] issuerserial optional,
 *                         -- the issuer and serial number of
 *                         -- the holder's public key certificate
 *                entityname          [1] generalnames optional,
 *                         -- the name of the claimant or role
 *                objectdigestinfo    [2] objectdigestinfo optional
 *                         -- used to directly authenticate the holder,
 *                         -- for example, an executable
 *          }
 * </pre>
 * @deprecated use org.bouncycastle.cert.attributecertificateholder
 */
public class attributecertificateholder
    implements certselector, selector
{
    final holder holder;

    attributecertificateholder(asn1sequence seq)
    {
        holder = holder.getinstance(seq);
    }

    public attributecertificateholder(x509principal issuername,
        biginteger serialnumber)
    {
        holder = new org.ripple.bouncycastle.asn1.x509.holder(new issuerserial(
            generalnames.getinstance(new dersequence(new generalname(issuername))),
            new asn1integer(serialnumber)));
    }

    public attributecertificateholder(x500principal issuername,
        biginteger serialnumber)
    {
        this(x509util.convertprincipal(issuername), serialnumber);
    }

    public attributecertificateholder(x509certificate cert)
        throws certificateparsingexception
    {
        x509principal name;

        try
        {
            name = principalutil.getissuerx509principal(cert);
        }
        catch (exception e)
        {
            throw new certificateparsingexception(e.getmessage());
        }

        holder = new holder(new issuerserial(generategeneralnames(name),
            new asn1integer(cert.getserialnumber())));
    }

    public attributecertificateholder(x509principal principal)
    {
        holder = new holder(generategeneralnames(principal));
    }

    public attributecertificateholder(x500principal principal)
    {
        this(x509util.convertprincipal(principal));
    }

    /**
     * constructs a holder for v2 attribute certificates with a hash value for
     * some type of object.
     * <p>
     * <code>digestedobjecttype</code> can be one of the following:
     * <ul>
     * <li>0 - publickey - a hash of the public key of the holder must be
     * passed.
     * <li>1 - publickeycert - a hash of the public key certificate of the
     * holder must be passed.
     * <li>2 - otherobjectdigest - a hash of some other object type must be
     * passed. <code>otherobjecttypeid</code> must not be empty.
     * </ul>
     * <p>
     * this cannot be used if a v1 attribute certificate is used.
     * 
     * @param digestedobjecttype the digest object type.
     * @param digestalgorithm the algorithm identifier for the hash.
     * @param otherobjecttypeid the object type id if
     *            <code>digestedobjecttype</code> is
     *            <code>otherobjectdigest</code>.
     * @param objectdigest the hash value.
     */
    public attributecertificateholder(int digestedobjecttype,
        string digestalgorithm, string otherobjecttypeid, byte[] objectdigest)
    {
        holder = new holder(new objectdigestinfo(digestedobjecttype,
            new asn1objectidentifier(otherobjecttypeid), new algorithmidentifier(digestalgorithm), arrays
                .clone(objectdigest)));
    }

    /**
     * returns the digest object type if an object digest info is used.
     * <p>
     * <ul>
     * <li>0 - publickey - a hash of the public key of the holder must be
     * passed.
     * <li>1 - publickeycert - a hash of the public key certificate of the
     * holder must be passed.
     * <li>2 - otherobjectdigest - a hash of some other object type must be
     * passed. <code>otherobjecttypeid</code> must not be empty.
     * </ul>
     * 
     * @return the digest object type or -1 if no object digest info is set.
     */
    public int getdigestedobjecttype()
    {
        if (holder.getobjectdigestinfo() != null)
        {
            return holder.getobjectdigestinfo().getdigestedobjecttype()
                .getvalue().intvalue();
        }
        return -1;
    }

    /**
     * returns the other object type id if an object digest info is used.
     * 
     * @return the other object type id or <code>null</code> if no object
     *         digest info is set.
     */
    public string getdigestalgorithm()
    {
        if (holder.getobjectdigestinfo() != null)
        {
            return holder.getobjectdigestinfo().getdigestalgorithm().getobjectid()
                .getid();
        }
        return null;
    }

    /**
     * returns the hash if an object digest info is used.
     * 
     * @return the hash or <code>null</code> if no object digest info is set.
     */
    public byte[] getobjectdigest()
    {
        if (holder.getobjectdigestinfo() != null)
        {
            return holder.getobjectdigestinfo().getobjectdigest().getbytes();
        }
        return null;
    }

    /**
     * returns the digest algorithm id if an object digest info is used.
     * 
     * @return the digest algorithm id or <code>null</code> if no object
     *         digest info is set.
     */
    public string getotherobjecttypeid()
    {
        if (holder.getobjectdigestinfo() != null)
        {
            holder.getobjectdigestinfo().getotherobjecttypeid().getid();
        }
        return null;
    }

    private generalnames generategeneralnames(x509principal principal)
    {
        return generalnames.getinstance(new dersequence(new generalname(principal)));
    }

    private boolean matchesdn(x509principal subject, generalnames targets)
    {
        generalname[] names = targets.getnames();

        for (int i = 0; i != names.length; i++)
        {
            generalname gn = names[i];

            if (gn.gettagno() == generalname.directoryname)
            {
                try
                {
                    if (new x509principal(((asn1encodable)gn.getname()).toasn1primitive()
                        .getencoded()).equals(subject))
                    {
                        return true;
                    }
                }
                catch (ioexception e)
                {
                }
            }
        }

        return false;
    }

    private object[] getnames(generalname[] names)
    {
        list l = new arraylist(names.length);

        for (int i = 0; i != names.length; i++)
        {
            if (names[i].gettagno() == generalname.directoryname)
            {
                try
                {
                    l.add(new x500principal(
                        ((asn1encodable)names[i].getname()).toasn1primitive().getencoded()));
                }
                catch (ioexception e)
                {
                    throw new runtimeexception("badly formed name object");
                }
            }
        }

        return l.toarray(new object[l.size()]);
    }

    private principal[] getprincipals(generalnames names)
    {
        object[] p = this.getnames(names.getnames());
        list l = new arraylist();

        for (int i = 0; i != p.length; i++)
        {
            if (p[i] instanceof principal)
            {
                l.add(p[i]);
            }
        }

        return (principal[])l.toarray(new principal[l.size()]);
    }

    /**
     * return any principal objects inside the attribute certificate holder
     * entity names field.
     * 
     * @return an array of principal objects (usually x500principal), null if no
     *         entity names field is set.
     */
    public principal[] getentitynames()
    {
        if (holder.getentityname() != null)
        {
            return getprincipals(holder.getentityname());
        }

        return null;
    }

    /**
     * return the principals associated with the issuer attached to this holder
     * 
     * @return an array of principals, null if no basecertificateid is set.
     */
    public principal[] getissuer()
    {
        if (holder.getbasecertificateid() != null)
        {
            return getprincipals(holder.getbasecertificateid().getissuer());
        }

        return null;
    }

    /**
     * return the serial number associated with the issuer attached to this
     * holder.
     * 
     * @return the certificate serial number, null if no basecertificateid is
     *         set.
     */
    public biginteger getserialnumber()
    {
        if (holder.getbasecertificateid() != null)
        {
            return holder.getbasecertificateid().getserial().getvalue();
        }

        return null;
    }

    public object clone()
    {
        return new attributecertificateholder((asn1sequence)holder
            .toasn1object());
    }

    public boolean match(certificate cert)
    {
        if (!(cert instanceof x509certificate))
        {
            return false;
        }

        x509certificate x509cert = (x509certificate)cert;

        try
        {
            if (holder.getbasecertificateid() != null)
            {
                return holder.getbasecertificateid().getserial().getvalue().equals(x509cert.getserialnumber())
                    && matchesdn(principalutil.getissuerx509principal(x509cert), holder.getbasecertificateid().getissuer());
            }

            if (holder.getentityname() != null)
            {
                if (matchesdn(principalutil.getsubjectx509principal(x509cert),
                    holder.getentityname()))
                {
                    return true;
                }
            }
            if (holder.getobjectdigestinfo() != null)
            {
                messagedigest md = null;
                try
                {
                    md = messagedigest.getinstance(getdigestalgorithm(), "bc");

                }
                catch (exception e)
                {
                    return false;
                }
                switch (getdigestedobjecttype())
                {
                case objectdigestinfo.publickey:
                    // todo: dsa dss-parms
                    md.update(cert.getpublickey().getencoded());
                    break;
                case objectdigestinfo.publickeycert:
                    md.update(cert.getencoded());
                    break;
                }
                if (!arrays.areequal(md.digest(), getobjectdigest()))
                {
                    return false;
                }
            }
        }
        catch (certificateencodingexception e)
        {
            return false;
        }

        return false;
    }

    public boolean equals(object obj)
    {
        if (obj == this)
        {
            return true;
        }

        if (!(obj instanceof attributecertificateholder))
        {
            return false;
        }

        attributecertificateholder other = (attributecertificateholder)obj;

        return this.holder.equals(other.holder);
    }

    public int hashcode()
    {
        return this.holder.hashcode();
    }

    public boolean match(object obj)
    {
        if (!(obj instanceof x509certificate))
        {
            return false;
        }

        return match((certificate)obj);
    }
}
