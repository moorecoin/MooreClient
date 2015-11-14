package org.ripple.bouncycastle.openpgp;

import java.io.bufferedinputstream;
import java.io.file;
import java.io.fileinputstream;
import java.io.ioexception;
import java.io.inputstream;
import java.io.outputstream;
import java.security.nosuchproviderexception;
import java.security.provider;
import java.security.securerandom;
import java.security.security;
import java.util.date;

import org.ripple.bouncycastle.asn1.asn1inputstream;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.derinteger;
import org.ripple.bouncycastle.bcpg.armoredinputstream;
import org.ripple.bouncycastle.bcpg.hashalgorithmtags;
import org.ripple.bouncycastle.bcpg.mpinteger;
import org.ripple.bouncycastle.bcpg.publickeyalgorithmtags;
import org.ripple.bouncycastle.bcpg.symmetrickeyalgorithmtags;
import org.ripple.bouncycastle.util.encoders.base64;

/**
 * basic utility class
 */
public class pgputil
    implements hashalgorithmtags
{
    private    static string    defprovider = "bc";

    /**
     * return the provider that will be used by factory classes in situations
     * where a provider must be determined on the fly.
     * 
     * @return string
     */
    public static string getdefaultprovider()
    {
        return defprovider;
    }
    
    /**
     * set the provider to be used by the package when it is necessary to 
     * find one on the fly.
     * 
     * @param provider
     */
    public static void setdefaultprovider(
        string    provider)
    {
        defprovider = provider;
    }
    
    static mpinteger[] dsasigtompi(
        byte[] encoding) 
        throws pgpexception
    {
        asn1inputstream ain = new asn1inputstream(encoding);

        derinteger i1;
        derinteger i2;

        try
        {
            asn1sequence s = (asn1sequence)ain.readobject();

            i1 = (derinteger)s.getobjectat(0);
            i2 = (derinteger)s.getobjectat(1);
        }
        catch (ioexception e)
        {
            throw new pgpexception("exception encoding signature", e);
        }

        mpinteger[] values = new mpinteger[2];
        
        values[0] = new mpinteger(i1.getvalue());
        values[1] = new mpinteger(i2.getvalue());
        
        return values;
    }
    
    static string getdigestname(
        int        hashalgorithm)
        throws pgpexception
    {
        switch (hashalgorithm)
        {
        case hashalgorithmtags.sha1:
            return "sha1";
        case hashalgorithmtags.md2:
            return "md2";
        case hashalgorithmtags.md5:
            return "md5";
        case hashalgorithmtags.ripemd160:
            return "ripemd160";
        case hashalgorithmtags.sha256:
            return "sha256";
        case hashalgorithmtags.sha384:
            return "sha384";
        case hashalgorithmtags.sha512:
            return "sha512";
        case hashalgorithmtags.sha224:
            return "sha224";
        default:
            throw new pgpexception("unknown hash algorithm tag in getdigestname: " + hashalgorithm);
        }
    }
    
    static string getsignaturename(
        int        keyalgorithm,
        int        hashalgorithm)
        throws pgpexception
    {
        string     encalg;
                
        switch (keyalgorithm)
        {
        case publickeyalgorithmtags.rsa_general:
        case publickeyalgorithmtags.rsa_sign:
            encalg = "rsa";
            break;
        case publickeyalgorithmtags.dsa:
            encalg = "dsa";
            break;
        case publickeyalgorithmtags.elgamal_encrypt: // in some malformed cases.
        case publickeyalgorithmtags.elgamal_general:
            encalg = "elgamal";
            break;
        default:
            throw new pgpexception("unknown algorithm tag in signature:" + keyalgorithm);
        }

        return getdigestname(hashalgorithm) + "with" + encalg;
    }

    public static byte[] makerandomkey(
        int             algorithm,
        securerandom    random) 
        throws pgpexception
    {
        int        keysize = 0;
        
        switch (algorithm)
        {
        case symmetrickeyalgorithmtags.triple_des:
            keysize = 192;
            break;
        case symmetrickeyalgorithmtags.idea:
            keysize = 128;
            break;
        case symmetrickeyalgorithmtags.cast5:
            keysize = 128;
            break;
        case symmetrickeyalgorithmtags.blowfish:
            keysize = 128;
            break;
        case symmetrickeyalgorithmtags.safer:
            keysize = 128;
            break;
        case symmetrickeyalgorithmtags.des:
            keysize = 64;
            break;
        case symmetrickeyalgorithmtags.aes_128:
            keysize = 128;
            break;
        case symmetrickeyalgorithmtags.aes_192:
            keysize = 192;
            break;
        case symmetrickeyalgorithmtags.aes_256:
            keysize = 256;
            break;
        case symmetrickeyalgorithmtags.twofish:
            keysize = 256;
            break;
        default:
            throw new pgpexception("unknown symmetric algorithm: " + algorithm);
        }
        
        byte[]    keybytes = new byte[(keysize + 7) / 8];
        
        random.nextbytes(keybytes);
        
        return keybytes;
    }

    /**
     * write out the passed in file as a literal data packet.
     * 
     * @param out
     * @param filetype the literaldata type for the file.
     * @param file
     * 
     * @throws ioexception
     */
    public static void writefiletoliteraldata(
        outputstream    out,
        char            filetype,
        file            file)
        throws ioexception
    {
        pgpliteraldatagenerator ldata = new pgpliteraldatagenerator();
        outputstream pout = ldata.open(out, filetype, file.getname(), file.length(), new date(file.lastmodified()));
        pipefilecontents(file, pout, 4096);
    }
    
    /**
     * write out the passed in file as a literal data packet in partial packet format.
     * 
     * @param out
     * @param filetype the literaldata type for the file.
     * @param file
     * @param buffer buffer to be used to chunk the file into partial packets.
     * 
     * @throws ioexception
     */
    public static void writefiletoliteraldata(
        outputstream    out,
        char            filetype,
        file            file,
        byte[]          buffer)
        throws ioexception
    {
        pgpliteraldatagenerator ldata = new pgpliteraldatagenerator();
        outputstream pout = ldata.open(out, filetype, file.getname(), new date(file.lastmodified()), buffer);
        pipefilecontents(file, pout, buffer.length);
    }

    private static void pipefilecontents(file file, outputstream pout, int bufsize) throws ioexception
    {
        fileinputstream in = new fileinputstream(file);
        byte[] buf = new byte[bufsize];

        int len;
        while ((len = in.read(buf)) > 0)
        {
            pout.write(buf, 0, len);
        }

        pout.close();
        in.close();
    }

    private static final int read_ahead = 60;
    
    private static boolean ispossiblybase64(
        int    ch)
    {
        return (ch >= 'a' && ch <= 'z') || (ch >= 'a' && ch <= 'z') 
                || (ch >= '0' && ch <= '9') || (ch == '+') || (ch == '/')
                || (ch == '\r') || (ch == '\n');
    }
    
    /**
     * return either an armoredinputstream or a bcpginputstream based on
     * whether the initial characters of the stream are binary pgp encodings or not.
     * 
     * @param in the stream to be wrapped
     * @return a bcpginputstream
     * @throws ioexception
     */
    public static inputstream getdecoderstream(
        inputstream    in) 
        throws ioexception
    {
        if (!in.marksupported())
        {
            in = new bufferedinputstreamext(in);
        }
        
        in.mark(read_ahead);
        
        int    ch = in.read();
        

        if ((ch & 0x80) != 0)
        {
            in.reset();
        
            return in;
        }
        else
        {
            if (!ispossiblybase64(ch))
            {
                in.reset();
        
                return new armoredinputstream(in);
            }
            
            byte[]  buf = new byte[read_ahead];
            int     count = 1;
            int     index = 1;
            
            buf[0] = (byte)ch;
            while (count != read_ahead && (ch = in.read()) >= 0)
            {
                if (!ispossiblybase64(ch))
                {
                    in.reset();
                    
                    return new armoredinputstream(in);
                }
                
                if (ch != '\n' && ch != '\r')
                {
                    buf[index++] = (byte)ch;
                }
                
                count++;
            }
            
            in.reset();
        
            //
            // nothing but new lines, little else, assume regular armoring
            //
            if (count < 4)
            {
                return new armoredinputstream(in);
            }
            
            //
            // test our non-blank data
            //
            byte[]    firstblock = new byte[8];
            
            system.arraycopy(buf, 0, firstblock, 0, firstblock.length);

            byte[]    decoded = base64.decode(firstblock);
            
            //
            // it's a base64 pgp block.
            //
            if ((decoded[0] & 0x80) != 0)
            {
                return new armoredinputstream(in, false);
            }
            
            return new armoredinputstream(in);
        }
    }

    static provider getprovider(string providername)
        throws nosuchproviderexception
    {
        provider prov = security.getprovider(providername);

        if (prov == null)
        {
            throw new nosuchproviderexception("provider " + providername + " not found.");
        }

        return prov;
    }
    
    static class bufferedinputstreamext extends bufferedinputstream
    {
        bufferedinputstreamext(inputstream input)
        {
            super(input);
        }

        public synchronized int available() throws ioexception
        {
            int result = super.available();
            if (result < 0)
            {
                result = integer.max_value;
            }
            return result;
        }
    }
}
