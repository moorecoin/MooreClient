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
import org.ripple.bouncycastle.pqc.asn1.mcelieceprivatekey;
import org.ripple.bouncycastle.pqc.asn1.mceliecepublickey;
import org.ripple.bouncycastle.pqc.jcajce.spec.mcelieceprivatekeyspec;
import org.ripple.bouncycastle.pqc.jcajce.spec.mceliecepublickeyspec;

/**
 * this class is used to translate between mceliece keys and key specifications.
 *
 * @see bcmcelieceprivatekey
 * @see mcelieceprivatekeyspec
 * @see bcmceliecepublickey
 * @see mceliecepublickeyspec
 */
public class mceliecekeyfactoryspi
    extends keyfactoryspi
{
    /**
     * the oid of the algorithm.
     */
    public static final string oid = "1.3.6.1.4.1.8301.3.1.3.4.1";

    /**
     * converts, if possible, a key specification into a
     * {@link bcmceliecepublickey}. currently, the following key specifications
     * are supported: {@link mceliecepublickeyspec}, {@link x509encodedkeyspec}.
     *
     * @param keyspec the key specification
     * @return the mceliece public key
     * @throws invalidkeyspecexception if the key specification is not supported.
     */
    public publickey generatepublic(keyspec keyspec)
        throws invalidkeyspecexception
    {
        if (keyspec instanceof mceliecepublickeyspec)
        {
            return new bcmceliecepublickey((mceliecepublickeyspec)keyspec);
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


                return new bcmceliecepublickey(new mceliecepublickeyspec(oid, t, n,
                    matrixg));
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
     * {@link bcmcelieceprivatekey}. currently, the following key specifications
     * are supported: {@link mcelieceprivatekeyspec},
     * {@link pkcs8encodedkeyspec}.
     *
     * @param keyspec the key specification
     * @return the mceliece private key
     * @throws invalidkeyspecexception if the keyspec is not supported.
     */
    public privatekey generateprivate(keyspec keyspec)
        throws invalidkeyspecexception
    {
        if (keyspec instanceof mcelieceprivatekeyspec)
        {
            return new bcmcelieceprivatekey((mcelieceprivatekeyspec)keyspec);
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

                // decode <sinv>
                byte[] encsinv = ((asn1octetstring)privkey.getobjectat(5)).getoctets();
                // decode <p1>
                byte[] encp1 = ((asn1octetstring)privkey.getobjectat(6)).getoctets();
                // decode <p2>
                byte[] encp2 = ((asn1octetstring)privkey.getobjectat(7)).getoctets();

                //decode <h>
                byte[] ench = ((asn1octetstring)privkey.getobjectat(8)).getoctets();

                // decode <qinv>
                asn1sequence qseq = (asn1sequence)privkey.getobjectat(9);
                byte[][] encqinv = new byte[qseq.size()][];
                for (int i = 0; i < qseq.size(); i++)
                {
                    encqinv[i] = ((asn1octetstring)qseq.getobjectat(i)).getoctets();
                }

                return new bcmcelieceprivatekey(new mcelieceprivatekeyspec(oid, n, k,
                    encfieldpoly, encgoppapoly, encsinv, encp1, encp2,
                    ench, encqinv));

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
     * <li>for mceliecepublickey: {@link x509encodedkeyspec},
     * {@link mceliecepublickeyspec}</li>
     * <li>for mcelieceprivatekey: {@link pkcs8encodedkeyspec},
     * {@link mcelieceprivatekeyspec}</li>.
     * </ul>
     *
     * @param key     the key
     * @param keyspec the key specification
     * @return the specification of the mceliece key
     * @throws invalidkeyspecexception if the key type or the key specification is not
     * supported.
     * @see bcmcelieceprivatekey
     * @see mcelieceprivatekeyspec
     * @see bcmceliecepublickey
     * @see mceliecepublickeyspec
     */
    public keyspec getkeyspec(key key, class keyspec)
        throws invalidkeyspecexception
    {
        if (key instanceof bcmcelieceprivatekey)
        {
            if (pkcs8encodedkeyspec.class.isassignablefrom(keyspec))
            {
                return new pkcs8encodedkeyspec(key.getencoded());
            }
            else if (mcelieceprivatekeyspec.class.isassignablefrom(keyspec))
            {
                bcmcelieceprivatekey privkey = (bcmcelieceprivatekey)key;
                return new mcelieceprivatekeyspec(oid, privkey.getn(), privkey
                    .getk(), privkey.getfield(), privkey.getgoppapoly(),
                    privkey.getsinv(), privkey.getp1(), privkey.getp2(),
                    privkey.geth(), privkey.getqinv());
            }
        }
        else if (key instanceof bcmceliecepublickey)
        {
            if (x509encodedkeyspec.class.isassignablefrom(keyspec))
            {
                return new x509encodedkeyspec(key.getencoded());
            }
            else if (mceliecepublickeyspec.class.isassignablefrom(keyspec))
            {
                bcmceliecepublickey pubkey = (bcmceliecepublickey)key;
                return new mceliecepublickeyspec(oid, pubkey.getn(), pubkey.gett(),
                    pubkey.getg());
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
     * the following "source" keys are supported: {@link bcmcelieceprivatekey},
     * {@link bcmceliecepublickey}.
     *
     * @param key the key
     * @return a key of a known key type
     * @throws invalidkeyexception if the key type is not supported.
     */
    public key translatekey(key key)
        throws invalidkeyexception
    {
        if ((key instanceof bcmcelieceprivatekey)
            || (key instanceof bcmceliecepublickey))
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
            mceliecepublickey key = mceliecepublickey.getinstance(innertype);
            return new bcmceliecepublickey(key.getoid().getid(), key.getn(), key.gett(), key.getg());
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
            mcelieceprivatekey key = mcelieceprivatekey.getinstance(innertype);
            return new bcmcelieceprivatekey(key.getoid().getid(), key.getn(), key.getk(), key.getfield(), key.getgoppapoly(), key.getsinv(), key.getp1(), key.getp2(), key.geth(), key.getqinv());
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
