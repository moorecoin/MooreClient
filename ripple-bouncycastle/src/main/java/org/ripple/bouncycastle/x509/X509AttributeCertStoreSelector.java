package org.ripple.bouncycastle.x509;

import java.io.ioexception;
import java.math.biginteger;
import java.security.cert.certificateexpiredexception;
import java.security.cert.certificatenotyetvalidexception;
import java.util.collection;
import java.util.collections;
import java.util.date;
import java.util.hashset;
import java.util.iterator;
import java.util.set;

import org.ripple.bouncycastle.asn1.asn1inputstream;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.deroctetstring;
import org.ripple.bouncycastle.asn1.x509.generalname;
import org.ripple.bouncycastle.asn1.x509.target;
import org.ripple.bouncycastle.asn1.x509.targetinformation;
import org.ripple.bouncycastle.asn1.x509.targets;
import org.ripple.bouncycastle.asn1.x509.x509extensions;
import org.ripple.bouncycastle.util.selector;

/**
 * this class is an <code>selector</code> like implementation to select
 * attribute certificates from a given set of criteria.
 * 
 * @see org.ripple.bouncycastle.x509.x509attributecertificate
 * @see org.ripple.bouncycastle.x509.x509store
 *  @deprecated use org.bouncycastle.cert.x509attributecertificateselector and org.bouncycastle.cert.x509attributecertificateselectorbuilder.
 */
public class x509attributecertstoreselector
    implements selector
{

    // todo: name constraints???

    private attributecertificateholder holder;

    private attributecertificateissuer issuer;

    private biginteger serialnumber;

    private date attributecertificatevalid;

    private x509attributecertificate attributecert;

    private collection targetnames = new hashset();

    private collection targetgroups = new hashset();

    public x509attributecertstoreselector()
    {
        super();
    }

    /**
     * decides if the given attribute certificate should be selected.
     * 
     * @param obj the attribute certificate which should be checked.
     * @return <code>true</code> if the attribute certificate can be selected,
     *         <code>false</code> otherwise.
     */
    public boolean match(object obj)
    {
        if (!(obj instanceof x509attributecertificate))
        {
            return false;
        }

        x509attributecertificate attrcert = (x509attributecertificate) obj;

        if (this.attributecert != null)
        {
            if (!this.attributecert.equals(attrcert))
            {
                return false;
            }
        }
        if (serialnumber != null)
        {
            if (!attrcert.getserialnumber().equals(serialnumber))
            {
                return false;
            }
        }
        if (holder != null)
        {
            if (!attrcert.getholder().equals(holder))
            {
                return false;
            }
        }
        if (issuer != null)
        {
            if (!attrcert.getissuer().equals(issuer))
            {
                return false;
            }
        }

        if (attributecertificatevalid != null)
        {
            try
            {
                attrcert.checkvalidity(attributecertificatevalid);
            }
            catch (certificateexpiredexception e)
            {
                return false;
            }
            catch (certificatenotyetvalidexception e)
            {
                return false;
            }
        }
        if (!targetnames.isempty() || !targetgroups.isempty())
        {

            byte[] targetinfoext = attrcert
                .getextensionvalue(x509extensions.targetinformation.getid());
            if (targetinfoext != null)
            {
                targetinformation targetinfo;
                try
                {
                    targetinfo = targetinformation
                        .getinstance(new asn1inputstream(
                            ((deroctetstring) deroctetstring
                                .frombytearray(targetinfoext)).getoctets())
                            .readobject());
                }
                catch (ioexception e)
                {
                    return false;
                }
                catch (illegalargumentexception e)
                {
                    return false;
                }
                targets[] targetss = targetinfo.gettargetsobjects();
                if (!targetnames.isempty())
                {
                    boolean found = false;

                    for (int i=0; i<targetss.length; i++)
                    {
                        targets t = targetss[i];
                        target[] targets = t.gettargets();
                        for (int j=0; j<targets.length; j++)
                        {
                            if (targetnames.contains(generalname.getinstance(targets[j]
                                                       .gettargetname())))
                            {
                                found = true;
                                break;
                            }
                        }
                    }
                    if (!found)
                    {
                        return false;
                    }
                }
                if (!targetgroups.isempty())
                {
                    boolean found = false;

                    for (int i=0; i<targetss.length; i++)
                    {
                        targets t = targetss[i];
                        target[] targets = t.gettargets();
                        for (int j=0; j<targets.length; j++)
                        {
                            if (targetgroups.contains(generalname.getinstance(targets[j]
                                                        .gettargetgroup())))
                            {
                                found = true;
                                break;
                            }
                        }
                    }
                    if (!found)
                    {
                        return false;
                    }
                }
            }
        }
        return true;
    }

    /**
     * returns a clone of this object.
     * 
     * @return the clone.
     */
    public object clone()
    {
        x509attributecertstoreselector sel = new x509attributecertstoreselector();
        sel.attributecert = attributecert;
        sel.attributecertificatevalid = getattributecertificatevalid();
        sel.holder = holder;
        sel.issuer = issuer;
        sel.serialnumber = serialnumber;
        sel.targetgroups = gettargetgroups();
        sel.targetnames = gettargetnames();
        return sel;
    }

    /**
     * returns the attribute certificate which must be matched.
     * 
     * @return returns the attribute certificate.
     */
    public x509attributecertificate getattributecert()
    {
        return attributecert;
    }

    /**
     * set the attribute certificate to be matched. if <code>null</code> is
     * given any will do.
     * 
     * @param attributecert the attribute certificate to set.
     */
    public void setattributecert(x509attributecertificate attributecert)
    {
        this.attributecert = attributecert;
    }

    /**
     * get the criteria for the validity.
     * 
     * @return returns the attributecertificatevalid.
     */
    public date getattributecertificatevalid()
    {
        if (attributecertificatevalid != null)
        {
            return new date(attributecertificatevalid.gettime());
        }

        return null;
    }

    /**
     * set the time, when the certificate must be valid. if <code>null</code>
     * is given any will do.
     * 
     * @param attributecertificatevalid the attribute certificate validation
     *            time to set.
     */
    public void setattributecertificatevalid(date attributecertificatevalid)
    {
        if (attributecertificatevalid != null)
        {
            this.attributecertificatevalid = new date(attributecertificatevalid
                .gettime());
        }
        else
        {
            this.attributecertificatevalid = null;
        }
    }

    /**
     * gets the holder.
     * 
     * @return returns the holder.
     */
    public attributecertificateholder getholder()
    {
        return holder;
    }

    /**
     * sets the holder. if <code>null</code> is given any will do.
     * 
     * @param holder the holder to set.
     */
    public void setholder(attributecertificateholder holder)
    {
        this.holder = holder;
    }

    /**
     * returns the issuer criterion.
     * 
     * @return returns the issuer.
     */
    public attributecertificateissuer getissuer()
    {
        return issuer;
    }

    /**
     * sets the issuer the attribute certificate must have. if <code>null</code>
     * is given any will do.
     * 
     * @param issuer the issuer to set.
     */
    public void setissuer(attributecertificateissuer issuer)
    {
        this.issuer = issuer;
    }

    /**
     * gets the serial number the attribute certificate must have.
     * 
     * @return returns the serialnumber.
     */
    public biginteger getserialnumber()
    {
        return serialnumber;
    }

    /**
     * sets the serial number the attribute certificate must have. if
     * <code>null</code> is given any will do.
     * 
     * @param serialnumber the serialnumber to set.
     */
    public void setserialnumber(biginteger serialnumber)
    {
        this.serialnumber = serialnumber;
    }

    /**
     * adds a target name criterion for the attribute certificate to the target
     * information extension criteria. the <code>x509attributecertificate</code>
     * must contain at least one of the specified target names.
     * <p>
     * each attribute certificate may contain a target information extension
     * limiting the servers where this attribute certificate can be used. if
     * this extension is not present, the attribute certificate is not targeted
     * and may be accepted by any server.
     *
     * @param name the name as a generalname (not <code>null</code>)
     */
    public void addtargetname(generalname name)
    {
        targetnames.add(name);
    }

    /**
     * adds a target name criterion for the attribute certificate to the target
     * information extension criteria. the <code>x509attributecertificate</code>
     * must contain at least one of the specified target names.
     * <p>
     * each attribute certificate may contain a target information extension
     * limiting the servers where this attribute certificate can be used. if
     * this extension is not present, the attribute certificate is not targeted
     * and may be accepted by any server.
     *
     * @param name a byte array containing the name in asn.1 der encoded form of a generalname
     * @throws ioexception if a parsing error occurs.
     */
    public void addtargetname(byte[] name) throws ioexception
    {
        addtargetname(generalname.getinstance(asn1primitive.frombytearray(name)));
    }

    /**
     * adds a collection with target names criteria. if <code>null</code> is
     * given any will do.
     * <p>
     * the collection consists of either generalname objects or byte[] arrays representing
     * der encoded generalname structures.
     * 
     * @param names a collection of target names.
     * @throws ioexception if a parsing error occurs.
     * @see #addtargetname(byte[])
     * @see #addtargetname(generalname)
     */
    public void settargetnames(collection names) throws ioexception
    {
        targetnames = extractgeneralnames(names);
    }

    /**
     * gets the target names. the collection consists of <code>generalname</code>
     * objects.
     * <p>
     * the returned collection is immutable.
     * 
     * @return the collection of target names
     * @see #settargetnames(collection)
     */
    public collection gettargetnames()
    {
        return collections.unmodifiablecollection(targetnames);
    }

    /**
     * adds a target group criterion for the attribute certificate to the target
     * information extension criteria. the <code>x509attributecertificate</code>
     * must contain at least one of the specified target groups.
     * <p>
     * each attribute certificate may contain a target information extension
     * limiting the servers where this attribute certificate can be used. if
     * this extension is not present, the attribute certificate is not targeted
     * and may be accepted by any server.
     *
     * @param group the group as generalname form (not <code>null</code>)
     */
    public void addtargetgroup(generalname group)
    {
        targetgroups.add(group);
    }

    /**
     * adds a target group criterion for the attribute certificate to the target
     * information extension criteria. the <code>x509attributecertificate</code>
     * must contain at least one of the specified target groups.
     * <p>
     * each attribute certificate may contain a target information extension
     * limiting the servers where this attribute certificate can be used. if
     * this extension is not present, the attribute certificate is not targeted
     * and may be accepted by any server.
     *
     * @param name a byte array containing the group in asn.1 der encoded form of a generalname
     * @throws ioexception if a parsing error occurs.
     */
    public void addtargetgroup(byte[] name) throws ioexception
    {
        addtargetgroup(generalname.getinstance(asn1primitive.frombytearray(name)));
    }

    /**
     * adds a collection with target groups criteria. if <code>null</code> is
     * given any will do.
     * <p>
     * the collection consists of <code>generalname</code> objects or <code>byte[]</code representing der
     * encoded generalnames.
     * 
     * @param names a collection of target groups.
     * @throws ioexception if a parsing error occurs.
     * @see #addtargetgroup(byte[])
     * @see #addtargetgroup(generalname)
     */
    public void settargetgroups(collection names) throws ioexception
    {
        targetgroups = extractgeneralnames(names);
    }



    /**
     * gets the target groups. the collection consists of <code>generalname</code> objects.
     * <p>
     * the returned collection is immutable.
     *
     * @return the collection of target groups.
     * @see #settargetgroups(collection)
     */
    public collection gettargetgroups()
    {
        return collections.unmodifiablecollection(targetgroups);
    }

    private set extractgeneralnames(collection names)
        throws ioexception
    {
        if (names == null || names.isempty())
        {
            return new hashset();
        }
        set temp = new hashset();
        for (iterator it = names.iterator(); it.hasnext();)
        {
            object o = it.next();
            if (o instanceof generalname)
            {
                temp.add(o);
            }
            else
            {
                temp.add(generalname.getinstance(asn1primitive.frombytearray((byte[])o)));
            }
        }
        return temp;
    }
}
