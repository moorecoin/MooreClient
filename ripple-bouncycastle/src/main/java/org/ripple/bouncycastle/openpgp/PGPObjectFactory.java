package org.ripple.bouncycastle.openpgp;

import java.io.bytearrayinputstream;
import java.io.ioexception;
import java.io.inputstream;
import java.util.arraylist;
import java.util.list;

import org.ripple.bouncycastle.bcpg.bcpginputstream;
import org.ripple.bouncycastle.bcpg.packettags;
import org.ripple.bouncycastle.openpgp.operator.keyfingerprintcalculator;
import org.ripple.bouncycastle.openpgp.operator.jcajce.jcakeyfingerprintcalculator;

/**
 * general class for reading a pgp object stream.
 * <p>
 * note: if this class finds a pgppublickey or a pgpsecretkey it
 * will create a pgppublickeyring, or a pgpsecretkeyring for each
 * key found. if all you are trying to do is read a key ring file use
 * either pgppublickeyringcollection or pgpsecretkeyringcollection.
 */
public class pgpobjectfactory
{
    private bcpginputstream in;
    private keyfingerprintcalculator fingerprintcalculator;

    public pgpobjectfactory(
        inputstream in)
    {
        this(in, new jcakeyfingerprintcalculator());
    }

    /**
     * create an object factor suitable for reading keys, key rings and key ring collections.
     *
     * @param in stream to read from
     * @param fingerprintcalculator  calculator to use in key finger print calculations.
     */
    public pgpobjectfactory(
        inputstream              in,
        keyfingerprintcalculator fingerprintcalculator)
    {
        this.in = new bcpginputstream(in);
        this.fingerprintcalculator = fingerprintcalculator;
    }

    public pgpobjectfactory(
        byte[] bytes)
    {
        this(new bytearrayinputstream(bytes));
    }

    /**
     * create an object factor suitable for reading keys, key rings and key ring collections.
     *
     * @param bytes stream to read from
     * @param fingerprintcalculator  calculator to use in key finger print calculations.
     */
    public pgpobjectfactory(
        byte[] bytes,
        keyfingerprintcalculator fingerprintcalculator)
    {
        this(new bytearrayinputstream(bytes), fingerprintcalculator);
    }

    /**
     * return the next object in the stream, or null if the end is reached.
     * 
     * @return object
     * @throws ioexception on a parse error
     */
    public object nextobject()
        throws ioexception
    {
        list l;

        switch (in.nextpackettag())
        {
        case -1:
            return null;
        case packettags.signature:
            l = new arraylist();
            
            while (in.nextpackettag() == packettags.signature)
            {
                try
                {
                    l.add(new pgpsignature(in));
                }
                catch (pgpexception e)
                {
                    throw new ioexception("can't create signature object: " + e);
                }
            }
            
            return new pgpsignaturelist((pgpsignature[])l.toarray(new pgpsignature[l.size()]));
        case packettags.secret_key:
            try
            {
                return new pgpsecretkeyring(in, fingerprintcalculator);
            }
            catch (pgpexception e)
            {
                throw new ioexception("can't create secret key object: " + e);
            }
        case packettags.public_key:
            return new pgppublickeyring(in, fingerprintcalculator);
        case packettags.public_subkey:
            try
            {
                return pgppublickeyring.readsubkey(in, fingerprintcalculator);
            }
            catch (pgpexception e)
            {
                throw new ioexception("processing error: " + e.getmessage());
            }
        case packettags.compressed_data:
            return new pgpcompresseddata(in);
        case packettags.literal_data:
            return new pgpliteraldata(in);
        case packettags.public_key_enc_session:
        case packettags.symmetric_key_enc_session:
            return new pgpencrypteddatalist(in);
        case packettags.one_pass_signature:
            l = new arraylist();
            
            while (in.nextpackettag() == packettags.one_pass_signature)
            {
                try
                {
                    l.add(new pgponepasssignature(in));
                }
                catch (pgpexception e)
                {
                    throw new ioexception("can't create one pass signature object: " + e);
                }
            }
            
            return new pgponepasssignaturelist((pgponepasssignature[])l.toarray(new pgponepasssignature[l.size()]));
        case packettags.marker:
            return new pgpmarker(in);
        case packettags.experimental_1:
        case packettags.experimental_2:
        case packettags.experimental_3:
        case packettags.experimental_4:
            return in.readpacket();
        }
        
        throw new ioexception("unknown object in stream: " + in.nextpackettag());
    }
}
