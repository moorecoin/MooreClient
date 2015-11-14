package org.ripple.bouncycastle.openpgp.operator;

import java.io.ioexception;
import java.io.outputstream;

import org.ripple.bouncycastle.bcpg.hashalgorithmtags;
import org.ripple.bouncycastle.bcpg.s2k;
import org.ripple.bouncycastle.bcpg.symmetrickeyalgorithmtags;
import org.ripple.bouncycastle.openpgp.pgpexception;
import org.ripple.bouncycastle.util.strings;

/**
 * basic utility class
 */
class pgputil
    implements hashalgorithmtags
{
    static byte[] makekeyfrompassphrase(
        pgpdigestcalculator digestcalculator,
        int     algorithm,
        s2k     s2k,
        char[]  passphrase)
        throws pgpexception
    {
        string    algname = null;
        int        keysize = 0;

        switch (algorithm)
        {
        case symmetrickeyalgorithmtags.triple_des:
            keysize = 192;
            algname = "des_ede";
            break;
        case symmetrickeyalgorithmtags.idea:
            keysize = 128;
            algname = "idea";
            break;
        case symmetrickeyalgorithmtags.cast5:
            keysize = 128;
            algname = "cast5";
            break;
        case symmetrickeyalgorithmtags.blowfish:
            keysize = 128;
            algname = "blowfish";
            break;
        case symmetrickeyalgorithmtags.safer:
            keysize = 128;
            algname = "safer";
            break;
        case symmetrickeyalgorithmtags.des:
            keysize = 64;
            algname = "des";
            break;
        case symmetrickeyalgorithmtags.aes_128:
            keysize = 128;
            algname = "aes";
            break;
        case symmetrickeyalgorithmtags.aes_192:
            keysize = 192;
            algname = "aes";
            break;
        case symmetrickeyalgorithmtags.aes_256:
            keysize = 256;
            algname = "aes";
            break;
        case symmetrickeyalgorithmtags.twofish:
            keysize = 256;
            algname = "twofish";
            break;
        default:
            throw new pgpexception("unknown symmetric algorithm: " + algorithm);
        }

        byte[]    pbytes = strings.toutf8bytearray(passphrase);
        byte[]    keybytes = new byte[(keysize + 7) / 8];

        int    generatedbytes = 0;
        int    loopcount = 0;

        if (s2k != null)
        {
            if (s2k.gethashalgorithm() != digestcalculator.getalgorithm())
            {
                throw new pgpexception("s2k/digestcalculator mismatch");
            }
        }
        else
        {
            if (digestcalculator.getalgorithm() != hashalgorithmtags.md5)
            {
                throw new pgpexception("digestcalculator not for md5");
            }
        }

        outputstream dout = digestcalculator.getoutputstream();

        try
        {
            while (generatedbytes < keybytes.length)
            {
                if (s2k != null)
                {
                    for (int i = 0; i != loopcount; i++)
                    {
                        dout.write(0);
                    }

                    byte[]    iv = s2k.getiv();

                    switch (s2k.gettype())
                    {
                    case s2k.simple:
                        dout.write(pbytes);
                        break;
                    case s2k.salted:
                        dout.write(iv);
                        dout.write(pbytes);
                        break;
                    case s2k.salted_and_iterated:
                        long    count = s2k.getiterationcount();
                        dout.write(iv);
                        dout.write(pbytes);

                        count -= iv.length + pbytes.length;

                        while (count > 0)
                        {
                            if (count < iv.length)
                            {
                                dout.write(iv, 0, (int)count);
                                break;
                            }
                            else
                            {
                                dout.write(iv);
                                count -= iv.length;
                            }

                            if (count < pbytes.length)
                            {
                                dout.write(pbytes, 0, (int)count);
                                count = 0;
                            }
                            else
                            {
                                dout.write(pbytes);
                                count -= pbytes.length;
                            }
                        }
                        break;
                    default:
                        throw new pgpexception("unknown s2k type: " + s2k.gettype());
                    }
                }
                else
                {
                    for (int i = 0; i != loopcount; i++)
                    {
                        dout.write((byte)0);
                    }

                    dout.write(pbytes);
                }

                dout.close();

                byte[]    dig = digestcalculator.getdigest();

                if (dig.length > (keybytes.length - generatedbytes))
                {
                    system.arraycopy(dig, 0, keybytes, generatedbytes, keybytes.length - generatedbytes);
                }
                else
                {
                    system.arraycopy(dig, 0, keybytes, generatedbytes, dig.length);
                }

                generatedbytes += dig.length;

                loopcount++;
            }
        }
        catch (ioexception e)
        {
            throw new pgpexception("exception calculating digest: " + e.getmessage(), e);
        }

        for (int i = 0; i != pbytes.length; i++)
        {
            pbytes[i] = 0;
        }

        return keybytes;
    }

    public static byte[] makekeyfrompassphrase(
        pgpdigestcalculatorprovider digcalcprovider,
        int     algorithm,
        s2k     s2k,
        char[]  passphrase)
        throws pgpexception
    {
        pgpdigestcalculator digestcalculator;

        if (s2k != null)
        {
            digestcalculator = digcalcprovider.get(s2k.gethashalgorithm());
        }
        else
        {
            digestcalculator = digcalcprovider.get(hashalgorithmtags.md5);
        }

        return makekeyfrompassphrase(digestcalculator, algorithm, s2k, passphrase);
    }
}
