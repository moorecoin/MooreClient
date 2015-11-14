package org.ripple.bouncycastle.jce;

import java.io.bytearrayoutputstream;
import java.io.ioexception;

import javax.crypto.mac;
import javax.crypto.secretkey;
import javax.crypto.secretkeyfactory;
import javax.crypto.spec.pbekeyspec;
import javax.crypto.spec.pbeparameterspec;

import org.ripple.bouncycastle.asn1.asn1inputstream;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.dernull;
import org.ripple.bouncycastle.asn1.derobjectidentifier;
import org.ripple.bouncycastle.asn1.deroctetstring;
import org.ripple.bouncycastle.asn1.deroutputstream;
import org.ripple.bouncycastle.asn1.pkcs.contentinfo;
import org.ripple.bouncycastle.asn1.pkcs.macdata;
import org.ripple.bouncycastle.asn1.pkcs.pfx;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;
import org.ripple.bouncycastle.asn1.x509.digestinfo;

/**
 * utility class for reencoding pkcs#12 files to definite length.
 */
public class pkcs12util
{
    /**
     * just re-encode the outer layer of the pkcs#12 file to definite length encoding.
     *
     * @param berpkcs12file - original pkcs#12 file
     * @return a byte array representing the der encoding of the pfx structure
     * @throws ioexception
     */
    public static byte[] converttodefinitelength(byte[] berpkcs12file)
        throws ioexception
    {
        bytearrayoutputstream bout = new bytearrayoutputstream();
        deroutputstream dout = new deroutputstream(bout);

        pfx pfx = pfx.getinstance(berpkcs12file);

        bout.reset();

        dout.writeobject(pfx);

        return bout.tobytearray();
    }

    /**
     * re-encode the pkcs#12 structure to definite length encoding at the inner layer
     * as well, recomputing the mac accordingly.
     *
     * @param berpkcs12file - original pkcs12 file.
     * @param provider - provider to use for mac calculation.
     * @return a byte array representing the der encoding of the pfx structure.
     * @throws ioexception on parsing, encoding errors.
     */
    public static byte[] converttodefinitelength(byte[] berpkcs12file, char[] passwd, string provider)
        throws ioexception
    {
        pfx pfx = pfx.getinstance(berpkcs12file);

        contentinfo info = pfx.getauthsafe();

        asn1octetstring content = asn1octetstring.getinstance(info.getcontent());

        bytearrayoutputstream bout = new bytearrayoutputstream();
        deroutputstream dout = new deroutputstream(bout);

        asn1inputstream contentin = new asn1inputstream(content.getoctets());
        asn1primitive obj = contentin.readobject();

        dout.writeobject(obj);

        info = new contentinfo(info.getcontenttype(), new deroctetstring(bout.tobytearray()));

        macdata mdata = pfx.getmacdata();
        try
        {
            int itcount = mdata.getiterationcount().intvalue();
            byte[] data = asn1octetstring.getinstance(info.getcontent()).getoctets();
            byte[] res = calculatepbemac(mdata.getmac().getalgorithmid().getobjectid(), mdata.getsalt(), itcount, passwd, data, provider);

            algorithmidentifier algid = new algorithmidentifier(mdata.getmac().getalgorithmid().getobjectid(), dernull.instance);
            digestinfo dinfo = new digestinfo(algid, res);

            mdata = new macdata(dinfo, mdata.getsalt(), itcount);
        }
        catch (exception e)
        {
            throw new ioexception("error constructing mac: " + e.tostring());
        }
        
        pfx = new pfx(info, mdata);

        bout.reset();
        
        dout.writeobject(pfx);
        
        return bout.tobytearray();
    }

    private static byte[] calculatepbemac(
        derobjectidentifier oid,
        byte[]              salt,
        int                 itcount,
        char[]              password,
        byte[]              data,
        string              provider)
        throws exception
    {
        secretkeyfactory keyfact = secretkeyfactory.getinstance(oid.getid(), provider);
        pbeparameterspec defparams = new pbeparameterspec(salt, itcount);
        pbekeyspec pbespec = new pbekeyspec(password);
        secretkey key = keyfact.generatesecret(pbespec);

        mac mac = mac.getinstance(oid.getid(), provider);
        mac.init(key, defparams);
        mac.update(data);

        return mac.dofinal();
    }
}
