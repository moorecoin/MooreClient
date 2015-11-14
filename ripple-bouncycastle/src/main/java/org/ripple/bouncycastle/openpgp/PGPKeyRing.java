package org.ripple.bouncycastle.openpgp;

import java.io.ioexception;
import java.io.inputstream;
import java.io.outputstream;
import java.util.arraylist;
import java.util.iterator;
import java.util.list;

import org.ripple.bouncycastle.bcpg.bcpginputstream;
import org.ripple.bouncycastle.bcpg.packet;
import org.ripple.bouncycastle.bcpg.packettags;
import org.ripple.bouncycastle.bcpg.signaturepacket;
import org.ripple.bouncycastle.bcpg.trustpacket;
import org.ripple.bouncycastle.bcpg.userattributepacket;
import org.ripple.bouncycastle.bcpg.useridpacket;

public abstract class pgpkeyring
{
    pgpkeyring()
    {
    }

    static bcpginputstream wrap(inputstream in)
    {
        if (in instanceof bcpginputstream)
        {
            return (bcpginputstream)in;
        }

        return new bcpginputstream(in);
    }

    static trustpacket readoptionaltrustpacket(
        bcpginputstream pin)
        throws ioexception
    {
        return (pin.nextpackettag() == packettags.trust)
            ?   (trustpacket) pin.readpacket()
            :   null;
    }

    static list readsignaturesandtrust(
        bcpginputstream pin)
        throws ioexception
    {
        try
        {
            list siglist = new arraylist();

            while (pin.nextpackettag() == packettags.signature)
            {
                signaturepacket signaturepacket = (signaturepacket)pin.readpacket();
                trustpacket trustpacket = readoptionaltrustpacket(pin);

                siglist.add(new pgpsignature(signaturepacket, trustpacket));
            }

            return siglist;
        }
        catch (pgpexception e)
        {
            throw new ioexception("can't create signature object: " + e.getmessage()
                + ", cause: " + e.getunderlyingexception().tostring());
        }
    }

    static void readuserids(
        bcpginputstream pin,
        list ids,
        list idtrusts,
        list idsigs)
        throws ioexception
    {
        while (pin.nextpackettag() == packettags.user_id
            || pin.nextpackettag() == packettags.user_attribute)
        {
            packet obj = pin.readpacket();
            if (obj instanceof useridpacket)
            {
                useridpacket id = (useridpacket)obj;
                ids.add(id.getid());
            }
            else
            {
                userattributepacket user = (userattributepacket)obj;
                ids.add(new pgpuserattributesubpacketvector(user.getsubpackets()));
            }

            idtrusts.add(readoptionaltrustpacket(pin));
            idsigs.add(readsignaturesandtrust(pin));
        }
    }

    /**
        * return the first public key in the ring.  in the case of a {@link pgpsecretkeyring}
        * this is also the public key of the master key pair.
        *
        * @return pgppublickey
        */
    public abstract pgppublickey getpublickey();

    /**
        * return an iterator containing all the public keys.
        *
        * @return iterator
        */
    public abstract iterator getpublickeys();

    /**
        * return the public key referred to by the passed in keyid if it
        * is present.
        *
        * @param keyid
        * @return pgppublickey
        */
    public abstract pgppublickey getpublickey(long keyid);

    public abstract void encode(outputstream outstream)
        throws ioexception;

    public abstract byte[] getencoded()
        throws ioexception;

}