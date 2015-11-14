package org.ripple.bouncycastle.pqc.jcajce.provider.rainbow;

import java.io.ioexception;
import java.security.invalidkeyexception;
import java.security.key;
import java.security.keyfactoryspi;
import java.security.privatekey;
import java.security.publickey;
import java.security.spec.invalidkeyspecexception;
import java.security.spec.keyspec;
import java.security.spec.pkcs8encodedkeyspec;
import java.security.spec.x509encodedkeyspec;

import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.pkcs.privatekeyinfo;
import org.ripple.bouncycastle.asn1.x509.subjectpublickeyinfo;
import org.ripple.bouncycastle.jcajce.provider.util.asymmetrickeyinfoconverter;
import org.ripple.bouncycastle.pqc.asn1.rainbowprivatekey;
import org.ripple.bouncycastle.pqc.asn1.rainbowpublickey;
import org.ripple.bouncycastle.pqc.jcajce.spec.rainbowprivatekeyspec;
import org.ripple.bouncycastle.pqc.jcajce.spec.rainbowpublickeyspec;


/**
 * this class transforms rainbow keys and rainbow key specifications.
 *
 * @see bcrainbowpublickey
 * @see rainbowpublickeyspec
 * @see bcrainbowprivatekey
 * @see rainbowprivatekeyspec
 */
public class rainbowkeyfactoryspi
    extends keyfactoryspi
    implements asymmetrickeyinfoconverter
{
    /**
     * converts, if possible, a key specification into a
     * {@link bcrainbowprivatekey}. currently, the following key specifications
     * are supported: {@link rainbowprivatekeyspec}, {@link pkcs8encodedkeyspec}.
     * <p/>
     * <p/>
     * <p/>
     * the asn.1 definition of the key structure is
     * <p/>
     * <pre>
     *   rainbowprivatekey ::= sequence {
     *     oid        object identifier         -- oid identifying the algorithm
     *     a1inv      sequence of octet string  -- inversed matrix of l1
     *     b1         octet string              -- translation vector of l1
     *     a2inv      sequence of octet string  -- inversed matrix of l2
     *     b2         octet string              -- translation vector of l2
     *     vi         octet string              -- num of elmts in each set s
     *     layers     sequence of layer         -- layers of f
     *   }
     *
     *   layer             ::= sequence of poly
     *   poly              ::= sequence {
     *     alpha      sequence of octet string
     *     beta       sequence of octet string
     *     gamma      octet string
     *     eta        octet
     *   }
     * </pre>
     * <p/>
     * <p/>
     *
     * @param keyspec the key specification
     * @return the rainbow private key
     * @throws invalidkeyspecexception if the keyspec is not supported.
     */
    public privatekey enginegenerateprivate(keyspec keyspec)
        throws invalidkeyspecexception
    {
        if (keyspec instanceof rainbowprivatekeyspec)
        {
            return new bcrainbowprivatekey((rainbowprivatekeyspec)keyspec);
        }
        else if (keyspec instanceof pkcs8encodedkeyspec)
        {
            // get the der-encoded key according to pkcs#8 from the spec
            byte[] enckey = ((pkcs8encodedkeyspec)keyspec).getencoded();

            try
            {
                return generateprivate(privatekeyinfo.getinstance(asn1primitive.frombytearray(enckey)));
            }
            catch (exception e)
            {
                throw new invalidkeyspecexception(e.tostring());
            }
        }

        throw new invalidkeyspecexception("unsupported key specification: "
            + keyspec.getclass() + ".");
    }

    /**
     * converts, if possible, a key specification into a
     * {@link bcrainbowpublickey}. currently, the following key specifications are
     * supported:{@link x509encodedkeyspec}.
     * <p/>
     * <p/>
     * <p/>
     * the asn.1 definition of a public key's structure is
     * <p/>
     * <pre>
     *    rainbowpublickey ::= sequence {
     *      oid            object identifier        -- oid identifying the algorithm
     *      doclength      integer                  -- length of signable msg
     *      coeffquadratic sequence of octet string -- quadratic (mixed) coefficients
     *      coeffsingular  sequence of octet string -- singular coefficients
     *      coeffscalar       octet string             -- scalar coefficients
     *       }
     * </pre>
     * <p/>
     * <p/>
     *
     * @param keyspec the key specification
     * @return the rainbow public key
     * @throws invalidkeyspecexception if the keyspec is not supported.
     */
    public publickey enginegeneratepublic(keyspec keyspec)
        throws invalidkeyspecexception
    {
        if (keyspec instanceof rainbowpublickeyspec)
        {
            return new bcrainbowpublickey((rainbowpublickeyspec)keyspec);
        }
        else if (keyspec instanceof x509encodedkeyspec)
        {
            // get the der-encoded key according to x.509 from the spec
            byte[] enckey = ((x509encodedkeyspec)keyspec).getencoded();

            // decode the subjectpublickeyinfo data structure to the pki object
            try
            {
                return generatepublic(subjectpublickeyinfo.getinstance(enckey));
            }
            catch (exception e)
            {
                throw new invalidkeyspecexception(e.tostring());
            }
        }

        throw new invalidkeyspecexception("unknown key specification: " + keyspec + ".");
    }

    /**
     * converts a given key into a key specification, if possible. currently the
     * following specs are supported:
     * <ul>
     * <li>for rainbowpublickey: x509encodedkeyspec, rainbowpublickeyspec
     * <li>for rainbowprivatekey: pkcs8encodedkeyspec, rainbowprivatekeyspec
     * </ul>
     *
     * @param key     the key
     * @param keyspec the key specification
     * @return the specification of the cmss key
     * @throws invalidkeyspecexception if the key type or key specification is not supported.
     */
    public final keyspec enginegetkeyspec(key key, class keyspec)
        throws invalidkeyspecexception
    {
        if (key instanceof bcrainbowprivatekey)
        {
            if (pkcs8encodedkeyspec.class.isassignablefrom(keyspec))
            {
                return new pkcs8encodedkeyspec(key.getencoded());
            }
            else if (rainbowprivatekeyspec.class.isassignablefrom(keyspec))
            {
                bcrainbowprivatekey privkey = (bcrainbowprivatekey)key;
                return new rainbowprivatekeyspec(privkey.getinva1(), privkey
                    .getb1(), privkey.getinva2(), privkey.getb2(), privkey
                    .getvi(), privkey.getlayers());
            }
        }
        else if (key instanceof bcrainbowpublickey)
        {
            if (x509encodedkeyspec.class.isassignablefrom(keyspec))
            {
                return new x509encodedkeyspec(key.getencoded());
            }
            else if (rainbowpublickeyspec.class.isassignablefrom(keyspec))
            {
                bcrainbowpublickey pubkey = (bcrainbowpublickey)key;
                return new rainbowpublickeyspec(pubkey.getdoclength(), pubkey
                    .getcoeffquadratic(), pubkey.getcoeffsingular(), pubkey
                    .getcoeffscalar());
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
     * translates a key into a form known by the flexiprovider. currently the
     * following key types are supported: rainbowprivatekey, rainbowpublickey.
     *
     * @param key the key
     * @return a key of a known key type
     * @throws invalidkeyexception if the key is not supported.
     */
    public final key enginetranslatekey(key key)
        throws invalidkeyexception
    {
        if (key instanceof bcrainbowprivatekey || key instanceof bcrainbowpublickey)
        {
            return key;
        }

        throw new invalidkeyexception("unsupported key type");
    }

    public privatekey generateprivate(privatekeyinfo keyinfo)
        throws ioexception
    {
        rainbowprivatekey pkey = rainbowprivatekey.getinstance(keyinfo.parseprivatekey());

        return new bcrainbowprivatekey(pkey.getinva1(), pkey.getb1(), pkey.getinva2(), pkey.getb2(), pkey.getvi(), pkey.getlayers());
    }

    public publickey generatepublic(subjectpublickeyinfo keyinfo)
        throws ioexception
    {
        rainbowpublickey pkey = rainbowpublickey.getinstance(keyinfo.parsepublickey());

        return new bcrainbowpublickey(pkey.getdoclength(), pkey.getcoeffquadratic(), pkey.getcoeffsingular(), pkey.getcoeffscalar());
    }
}
