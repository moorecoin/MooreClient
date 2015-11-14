package org.ripple.bouncycastle.pqc.jcajce.provider.mceliece;

import java.io.ioexception;
import java.math.biginteger;
import java.security.invalidkeyexception;
import java.security.key;
import java.security.keyfactoryspi;
import java.security.privatekey;
import java.security.publickey;
import java.security.spec.invalidkeyspecexception;
import java.security.spec.keyspec;
import java.security.spec.pkcs8encodedkeyspec;
import java.security.spec.x509encodedkeyspec;

import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.pkcs.privatekeyinfo;
import org.ripple.bouncycastle.asn1.x509.subjectpublickeyinfo;
import org.ripple.bouncycastle.pqc.asn1.mceliececca2privatekey;
import org.ripple.bouncycastle.pqc.asn1.mceliececca2publickey;
import org.ripple.bouncycastle.pqc.jcajce.spec.mceliececca2privatekeyspec;
import org.ripple.bouncycastle.pqc.jcajce.spec.mceliececca2publickeyspec;

/**
 * this class is used to translate between mceliece cca2 keys and key
 * specifications.
 *
 * @see bcmceliececca2privatekey
 * @see mceliececca2privatekeyspec
 * @see bcmceliececca2publickey
 * @see mceliececca2publickeyspec
 */
public class mceliececca2keyfactoryspi
    extends keyfactoryspi
{

    /**
     * the oid of the algorithm.
     */
    public static final string oid = "1.3.6.1.4.1.8301.3.1.3.4.2";

    /**
     * converts, if possible, a key specification into a
     * {@link bcmceliececca2publickey}. currently, the following key
     * specifications are supported: {@link mceliececca2publickeyspec},
     * {@link x509encodedkeyspec}.
     *
     * @param keyspec the key specification
     * @return the mceliece cca2 public key
     * @throws invalidkeyspecexception if the key specification is not supported.
     */
    public publickey generatepublic(keyspec keyspec)
        throws invalidkeyspecexception
    {
        if (keyspec instanceof mceliececca2publickeyspec)
        {
            return new bcmceliececca2publickey(
                (mceliececca2publickeyspec)keyspec);
        }
        else if (keyspec instanceof x509encodedkeyspec)
        {
            // get the der-encoded key according to x.509 from the spec
            byte[] enckey = ((x509encodedkeyspec)keyspec).getencoded();

            // decode the subjectpublickeyinfo data structure to the pki object
            subjectpublickeyinfo pki;
            try
            {
                pki = subjectpublickeyinfo.getinstance(asn1primitive.frombytearray(enckey));
            }
            catch (ioexception e)
            {
                throw new invalidkeyspecexception(e.tostring());
            }


            try
            {
                // --- build and return the actual key.
                asn1primitive innertype = pki.parsepublickey();
                asn1sequence publickey = (asn1sequence)innertype;

                // decode oidstring (but we don't need it right now)
                string oidstring = ((asn1objectidentifier)publickey.getobjectat(0))
                    .tostring();

                // decode <n>
                biginteger bign = ((asn1integer)publickey.getobjectat(1)).getvalue();
                int n = bign.intvalue();

                // decode <t>
                biginteger bigt = ((asn1integer)publickey.getobjectat(2)).getvalue();
                int t = bigt.intvalue();

                // decode <matrixg>
                byte[] matrixg = ((asn1octetstring)publickey.getobjectat(3)).getoctets();

                return new bcmceliececca2publickey(new mceliececca2publickeyspec(
                    oid, n, t, matrixg));
            }
            catch (ioexception cce)
            {
                throw new invalidkeyspecexception(
                    "unable to decode x509encodedkeyspec: "
                        + cce.getmessage());
            }
        }

        throw new invalidkeyspecexception("unsupported key specification: "
            + keyspec.getclass() + ".");
    }

    /**
     * converts, if possible, a key specification into a
     * {@link bcmceliececca2privatekey}. currently, the following key
     * specifications are supported: {@link mceliececca2privatekeyspec},
     * {@link pkcs8encodedkeyspec}.
     *
     * @param keyspec the key specification
     * @return the mceliece cca2 private key
     * @throws invalidkeyspecexception if the keyspec is not supported.
     */
    public privatekey generateprivate(keyspec keyspec)
        throws invalidkeyspecexception
    {
        if (keyspec instanceof mceliececca2privatekeyspec)
        {
            return new bcmceliececca2privatekey(
                (mceliececca2privatekeyspec)keyspec);
        }
        else if (keyspec instanceof pkcs8encodedkeyspec)
        {
            // get the der-encoded key according to pkcs#8 from the spec
            byte[] enckey = ((pkcs8encodedkeyspec)keyspec).getencoded();

            // decode the pkcs#8 data structure to the pki object
            privatekeyinfo pki;

            try
            {
                pki = privatekeyinfo.getinstance(asn1primitive.frombytearray(enckey));
            }
            catch (ioexception e)
            {
                throw new invalidkeyspecexception("unable to decode pkcs8encodedkeyspec: " + e);
            }

            try
            {
                // get the inner type inside the bit string
                asn1primitive innertype = pki.parseprivatekey().toasn1primitive();

                // build and return the actual key
                asn1sequence privkey = (asn1sequence)innertype;

                // decode oidstring (but we don't need it right now)
                string oidstring = ((asn1objectidentifier)privkey.getobjectat(0))
                    .tostring();

                // decode <n>
                biginteger bign = ((asn1integer)privkey.getobjectat(1)).getvalue();
                int n = bign.intvalue();

                // decode <k>
                biginteger bigk = ((asn1integer)privkey.getobjectat(2)).getvalue();
                int k = bigk.intvalue();


                // decode <fieldpoly>
                byte[] encfieldpoly = ((asn1octetstring)privkey.getobjectat(3))
                    .getoctets();
                // decode <goppapoly>
                byte[] encgoppapoly = ((asn1octetstring)privkey.getobjectat(4))
                    .getoctets();
                // decode <p>
                byte[] encp = ((asn1octetstring)privkey.getobjectat(5)).getoctets();
                // decode <h>
                byte[] ench = ((asn1octetstring)privkey.getobjectat(6)).getoctets();
                // decode <qinv>
                asn1sequence qseq = (asn1sequence)privkey.getobjectat(7);
                byte[][] encqinv = new byte[qseq.size()][];
                for (int i = 0; i < qseq.size(); i++)
                {
                    encqinv[i] = ((asn1octetstring)qseq.getobjectat(i)).getoctets();
                }

                return new bcmceliececca2privatekey(
                    new mceliececca2privatekeyspec(oid, n, k, encfieldpoly,
                        encgoppapoly, encp, ench, encqinv));

            }
            catch (ioexception cce)
            {
                throw new invalidkeyspecexception(
                    "unable to decode pkcs8encodedkeyspec.");
            }
        }

        throw new invalidkeyspecexception("unsupported key specification: "
            + keyspec.getclass() + ".");
    }

    /**
     * converts, if possible, a given key into a key specification. currently,
     * the following key specifications are supported:
     * <ul>
     * <li>for mceliececca2publickey: {@link x509encodedkeyspec},
     * {@link mceliececca2publickeyspec}</li>
     * <li>for mceliececca2privatekey: {@link pkcs8encodedkeyspec},
     * {@link mceliececca2privatekeyspec}</li>.
     * </ul>
     *
     * @param key     the key
     * @param keyspec the key specification
     * @return the specification of the mceliece cca2 key
     * @throws invalidkeyspecexception if the key type or the key specification is not
     * supported.
     * @see bcmceliececca2privatekey
     * @see mceliececca2privatekeyspec
     * @see bcmceliececca2publickey
     * @see mceliececca2publickeyspec
     */
    public keyspec getkeyspec(key key, class keyspec)
        throws invalidkeyspecexception
    {
        if (key instanceof bcmceliececca2privatekey)
        {
            if (pkcs8encodedkeyspec.class.isassignablefrom(keyspec))
            {
                return new pkcs8encodedkeyspec(key.getencoded());
            }
            else if (mceliececca2privatekeyspec.class
                .isassignablefrom(keyspec))
            {
                bcmceliececca2privatekey privkey = (bcmceliececca2privatekey)key;
                return new mceliececca2privatekeyspec(oid, privkey.getn(), privkey
                    .getk(), privkey.getfield(), privkey.getgoppapoly(),
                    privkey.getp(), privkey.geth(), privkey.getqinv());
            }
        }
        else if (key instanceof bcmceliececca2publickey)
        {
            if (x509encodedkeyspec.class.isassignablefrom(keyspec))
            {
                return new x509encodedkeyspec(key.getencoded());
            }
            else if (mceliececca2publickeyspec.class
                .isassignablefrom(keyspec))
            {
                bcmceliececca2publickey pubkey = (bcmceliececca2publickey)key;
                return new mceliececca2publickeyspec(oid, pubkey.getn(), pubkey
                    .gett(), pubkey.getg());
            }
        }
        else
        {
            throw new invalidkeyspecexception("unsupported key type: "
                + key.getclass() + ".");
        }

        throw new invalidkeyspecexception("unknown key specification: "
            + keyspec + ".");
    }

    /**
     * translates a key into a form known by the flexiprovider. currently, only
     * the following "source" keys are supported: {@link bcmceliececca2privatekey},
     * {@link bcmceliececca2publickey}.
     *
     * @param key the key
     * @return a key of a known key type
     * @throws invalidkeyexception if the key type is not supported.
     */
    public key translatekey(key key)
        throws invalidkeyexception
    {
        if ((key instanceof bcmceliececca2privatekey)
            || (key instanceof bcmceliececca2publickey))
        {
            return key;
        }
        throw new invalidkeyexception("unsupported key type.");

    }


    public publickey generatepublic(subjectpublickeyinfo pki)
        throws invalidkeyspecexception
    {
        // get the inner type inside the bit string
        try
        {
            asn1primitive innertype = pki.parsepublickey();
            mceliececca2publickey key = mceliececca2publickey.getinstance((asn1sequence)innertype);
            return new bcmceliececca2publickey(key.getoid().getid(), key.getn(), key.gett(), key.getg());
        }
        catch (ioexception cce)
        {
            throw new invalidkeyspecexception("unable to decode x509encodedkeyspec");
        }
    }


    public privatekey generateprivate(privatekeyinfo pki)
        throws invalidkeyspecexception
    {
        // get the inner type inside the bit string
        try
        {
            asn1primitive innertype = pki.parseprivatekey().toasn1primitive();
            mceliececca2privatekey key = mceliececca2privatekey.getinstance(innertype);
            return new bcmceliececca2privatekey(key.getoid().getid(), key.getn(), key.getk(), key.getfield(), key.getgoppapoly(), key.getp(), key.geth(), key.getqinv());
        }
        catch (ioexception cce)
        {
            throw new invalidkeyspecexception("unable to decode pkcs8encodedkeyspec");
        }
    }

    protected publickey enginegeneratepublic(keyspec keyspec)
        throws invalidkeyspecexception
    {
        return null;  //to change body of implemented methods use file | settings | file templates.
    }

    protected privatekey enginegenerateprivate(keyspec keyspec)
        throws invalidkeyspecexception
    {
        return null;  //to change body of implemented methods use file | settings | file templates.
    }

    protected keyspec enginegetkeyspec(key key, class tclass)
        throws invalidkeyspecexception
    {
        return null;  //to change body of implemented methods use file | settings | file templates.
    }

    protected key enginetranslatekey(key key)
        throws invalidkeyexception
    {
        return null;  //to change body of implemented methods use file | settings | file templates.
    }
}
