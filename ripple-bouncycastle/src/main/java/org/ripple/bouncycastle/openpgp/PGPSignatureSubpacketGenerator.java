package org.ripple.bouncycastle.openpgp;

import java.io.ioexception;
import java.util.arraylist;
import java.util.date;
import java.util.list;

import org.ripple.bouncycastle.bcpg.signaturesubpacket;
import org.ripple.bouncycastle.bcpg.signaturesubpackettags;
import org.ripple.bouncycastle.bcpg.sig.embeddedsignature;
import org.ripple.bouncycastle.bcpg.sig.exportable;
import org.ripple.bouncycastle.bcpg.sig.features;
import org.ripple.bouncycastle.bcpg.sig.issuerkeyid;
import org.ripple.bouncycastle.bcpg.sig.keyexpirationtime;
import org.ripple.bouncycastle.bcpg.sig.keyflags;
import org.ripple.bouncycastle.bcpg.sig.notationdata;
import org.ripple.bouncycastle.bcpg.sig.preferredalgorithms;
import org.ripple.bouncycastle.bcpg.sig.primaryuserid;
import org.ripple.bouncycastle.bcpg.sig.revocable;
import org.ripple.bouncycastle.bcpg.sig.revocationkey;
import org.ripple.bouncycastle.bcpg.sig.revocationkeytags;
import org.ripple.bouncycastle.bcpg.sig.revocationreason;
import org.ripple.bouncycastle.bcpg.sig.signaturecreationtime;
import org.ripple.bouncycastle.bcpg.sig.signatureexpirationtime;
import org.ripple.bouncycastle.bcpg.sig.signeruserid;
import org.ripple.bouncycastle.bcpg.sig.trustsignature;

/**
 * generator for signature subpackets.
 */
public class pgpsignaturesubpacketgenerator
{
    list list = new arraylist();

    public pgpsignaturesubpacketgenerator()
    {
    }

    public void setrevocable(boolean iscritical, boolean isrevocable)
    {
        list.add(new revocable(iscritical, isrevocable));
    }

    public void setexportable(boolean iscritical, boolean isexportable)
    {
        list.add(new exportable(iscritical, isexportable));
    }

    public void setfeature(boolean iscritical, byte feature)
    {
        list.add(new features(iscritical, feature));
    }

    /**
     * add a trustsignature packet to the signature. the values for depth and trust are
     * largely installation dependent but there are some guidelines in rfc 4880 -
     * 5.2.3.13.
     * 
     * @param iscritical true if the packet is critical.
     * @param depth depth level.
     * @param trustamount trust amount.
     */
    public void settrust(boolean iscritical, int depth, int trustamount)
    {
        list.add(new trustsignature(iscritical, depth, trustamount));
    }

    /**
     * set the number of seconds a key is valid for after the time of its creation. a
     * value of zero means the key never expires.
     * 
     * @param iscritical true if should be treated as critical, false otherwise.
     * @param seconds
     */
    public void setkeyexpirationtime(boolean iscritical, long seconds)
    {
        list.add(new keyexpirationtime(iscritical, seconds));
    }

    /**
     * set the number of seconds a signature is valid for after the time of its creation.
     * a value of zero means the signature never expires.
     * 
     * @param iscritical true if should be treated as critical, false otherwise.
     * @param seconds
     */
    public void setsignatureexpirationtime(boolean iscritical, long seconds)
    {
        list.add(new signatureexpirationtime(iscritical, seconds));
    }

    /**
     * set the creation time for the signature.
     * <p>
     * note: this overrides the generation of a creation time when the signature is
     * generated.
     */
    public void setsignaturecreationtime(boolean iscritical, date date)
    {
        list.add(new signaturecreationtime(iscritical, date));
    }

    public void setpreferredhashalgorithms(boolean iscritical, int[] algorithms)
    {
        list.add(new preferredalgorithms(signaturesubpackettags.preferred_hash_algs, iscritical,
            algorithms));
    }

    public void setpreferredsymmetricalgorithms(boolean iscritical, int[] algorithms)
    {
        list.add(new preferredalgorithms(signaturesubpackettags.preferred_sym_algs, iscritical,
            algorithms));
    }

    public void setpreferredcompressionalgorithms(boolean iscritical, int[] algorithms)
    {
        list.add(new preferredalgorithms(signaturesubpackettags.preferred_comp_algs, iscritical,
            algorithms));
    }

    public void setkeyflags(boolean iscritical, int flags)
    {
        list.add(new keyflags(iscritical, flags));
    }

    public void setsigneruserid(boolean iscritical, string userid)
    {
        if (userid == null)
        {
            throw new illegalargumentexception("attempt to set null signeruserid");
        }

        list.add(new signeruserid(iscritical, userid));
    }

    public void setembeddedsignature(boolean iscritical, pgpsignature pgpsignature)
        throws ioexception
    {
        byte[] sig = pgpsignature.getencoded();
        byte[] data;

        if (sig.length - 1 > 256)
        {
            data = new byte[sig.length - 3];
        }
        else
        {
            data = new byte[sig.length - 2];
        }

        system.arraycopy(sig, sig.length - data.length, data, 0, data.length);

        list.add(new embeddedsignature(iscritical, data));
    }

    public void setprimaryuserid(boolean iscritical, boolean isprimaryuserid)
    {
        list.add(new primaryuserid(iscritical, isprimaryuserid));
    }

    public void setnotationdata(boolean iscritical, boolean ishumanreadable, string notationname,
        string notationvalue)
    {
        list.add(new notationdata(iscritical, ishumanreadable, notationname, notationvalue));
    }

    /**
     * sets revocation reason sub packet
     */
    public void setrevocationreason(boolean iscritical, byte reason, string description)
    {
        list.add(new revocationreason(iscritical, reason, description));
    }

    /**
     * sets revocation key sub packet
     */
    public void setrevocationkey(boolean iscritical, int keyalgorithm, byte[] fingerprint)
    {
        list.add(new revocationkey(iscritical, revocationkeytags.class_default, keyalgorithm,
            fingerprint));
    }

    /**
     * sets issuer key sub packe
     */
    public void setissuerkeyid(boolean iscritical, long keyid)
    {
        list.add(new issuerkeyid(iscritical, keyid));
    }

    public pgpsignaturesubpacketvector generate()
    {
        return new pgpsignaturesubpacketvector(
            (signaturesubpacket[])list.toarray(new signaturesubpacket[list.size()]));
    }
}
