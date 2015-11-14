package org.ripple.bouncycastle.bcpg;

import org.ripple.bouncycastle.bcpg.sig.issuerkeyid;
import org.ripple.bouncycastle.bcpg.sig.signaturecreationtime;
import org.ripple.bouncycastle.util.arrays;

import java.io.bytearrayinputstream;
import java.io.bytearrayoutputstream;
import java.io.ioexception;
import java.util.vector;

/**
 * generic signature packet
 */
public class signaturepacket 
    extends containedpacket implements publickeyalgorithmtags
{
    private int                    version;
    private int                    signaturetype;
    private long                   creationtime;
    private long                   keyid;
    private int                    keyalgorithm;
    private int                    hashalgorithm;
    private mpinteger[]            signature;
    private byte[]                 fingerprint;
    private signaturesubpacket[]   hasheddata;
    private signaturesubpacket[]   unhasheddata;
    private byte[]                 signatureencoding;
    
    signaturepacket(
        bcpginputstream    in)
        throws ioexception
    {
        version = in.read();
        
        if (version == 3 || version == 2)
        {
            int    l = in.read();
            
            signaturetype = in.read();
            creationtime = (((long)in.read() << 24) | (in.read() << 16) | (in.read() << 8) | in.read()) * 1000;
            keyid |= (long)in.read() << 56;
            keyid |= (long)in.read() << 48;
            keyid |= (long)in.read() << 40;
            keyid |= (long)in.read() << 32;
            keyid |= (long)in.read() << 24;
            keyid |= (long)in.read() << 16;
            keyid |= (long)in.read() << 8;
            keyid |= in.read();
            keyalgorithm = in.read();
            hashalgorithm = in.read();
        }
        else if (version == 4)
        {
            signaturetype = in.read();
            keyalgorithm = in.read();
            hashalgorithm = in.read();
            
            int        hashedlength = (in.read() << 8) | in.read();
            byte[]    hashed = new byte[hashedlength];
            
            in.readfully(hashed);

            //
            // read the signature sub packet data.
            //
            signaturesubpacket    sub;
            signaturesubpacketinputstream    sin = new signaturesubpacketinputstream(
                                                                 new bytearrayinputstream(hashed));

            vector    v = new vector();
            while ((sub = sin.readpacket()) != null)
            {
                v.addelement(sub);
            }
            
            hasheddata = new signaturesubpacket[v.size()];
            
            for (int i = 0; i != hasheddata.length; i++)
            {
                signaturesubpacket    p = (signaturesubpacket)v.elementat(i);
                if (p instanceof issuerkeyid)
                {
                    keyid = ((issuerkeyid)p).getkeyid();
                }
                else if (p instanceof signaturecreationtime)
                {
                    creationtime = ((signaturecreationtime)p).gettime().gettime();
                }
                
                hasheddata[i] = p;
            }
            
            int        unhashedlength = (in.read() << 8) | in.read();
            byte[]    unhashed = new byte[unhashedlength];
            
            in.readfully(unhashed);
            
            sin = new signaturesubpacketinputstream(
                                     new bytearrayinputstream(unhashed));
                                                    
            v.removeallelements();
            while ((sub = sin.readpacket()) != null)
            {
                v.addelement(sub);
            }
            
            unhasheddata = new signaturesubpacket[v.size()];
            
            for (int i = 0; i != unhasheddata.length; i++)
            {
                signaturesubpacket    p = (signaturesubpacket)v.elementat(i);
                if (p instanceof issuerkeyid)
                {
                    keyid = ((issuerkeyid)p).getkeyid();
                }
                
                unhasheddata[i] = p;
            }
        }
        else
        {
            throw new runtimeexception("unsupported version: " + version);
        }
        
        fingerprint = new byte[2];
        in.readfully(fingerprint);
        
        switch (keyalgorithm)
        {
        case rsa_general:
        case rsa_sign:
            mpinteger    v = new mpinteger(in);
                
            signature = new mpinteger[1];
            signature[0] = v;
            break;
        case dsa:
            mpinteger    r = new mpinteger(in);
            mpinteger    s = new mpinteger(in);
                
            signature = new mpinteger[2];
            signature[0] = r;
            signature[1] = s;
            break;
        case elgamal_encrypt: // yep, this really does happen sometimes.
        case elgamal_general:
            mpinteger       p = new mpinteger(in);
            mpinteger       g = new mpinteger(in);
            mpinteger       y = new mpinteger(in);
            
            signature = new mpinteger[3];
            signature[0] = p;
            signature[1] = g;
            signature[2] = y;
            break;
        default:
            if (keyalgorithm >= publickeyalgorithmtags.experimental_1 && keyalgorithm <= publickeyalgorithmtags.experimental_11)
            {
                signature = null;
                bytearrayoutputstream bout = new bytearrayoutputstream();
                int ch;
                while ((ch = in.read()) >= 0)
                {
                    bout.write(ch);
                }
                signatureencoding = bout.tobytearray();
            }
            else
            {
                throw new ioexception("unknown signature key algorithm: " + keyalgorithm);
            }
        }
    }
    
    /**
     * generate a version 4 signature packet.
     * 
     * @param signaturetype
     * @param keyalgorithm
     * @param hashalgorithm
     * @param hasheddata
     * @param unhasheddata
     * @param fingerprint
     * @param signature
     */
    public signaturepacket(
        int                     signaturetype,
        long                    keyid,
        int                     keyalgorithm,
        int                     hashalgorithm,
        signaturesubpacket[]    hasheddata,
        signaturesubpacket[]    unhasheddata,
        byte[]                  fingerprint,
        mpinteger[]             signature)
    {
        this(4, signaturetype, keyid, keyalgorithm, hashalgorithm, hasheddata, unhasheddata, fingerprint, signature);
    }
    
    /**
     * generate a version 2/3 signature packet.
     * 
     * @param signaturetype
     * @param keyalgorithm
     * @param hashalgorithm
     * @param fingerprint
     * @param signature
     */
    public signaturepacket(
        int                     version,
        int                     signaturetype,
        long                    keyid,
        int                     keyalgorithm,
        int                     hashalgorithm,
        long                    creationtime,
        byte[]                  fingerprint,
        mpinteger[]             signature)
    {
        this(version, signaturetype, keyid, keyalgorithm, hashalgorithm, null, null, fingerprint, signature);
        
        this.creationtime = creationtime;
    }
    
    public signaturepacket(
        int                     version,
        int                     signaturetype,
        long                    keyid,
        int                     keyalgorithm,
        int                     hashalgorithm,
        signaturesubpacket[]    hasheddata,
        signaturesubpacket[]    unhasheddata,
        byte[]                  fingerprint,
        mpinteger[]             signature)
    {
        this.version = version;
        this.signaturetype = signaturetype;
        this.keyid = keyid;
        this.keyalgorithm = keyalgorithm;
        this.hashalgorithm = hashalgorithm;
        this.hasheddata = hasheddata;
        this.unhasheddata = unhasheddata;
        this.fingerprint = fingerprint;
        this.signature = signature;

        if (hasheddata != null)
        {
            setcreationtime();
        }
    }
    
    /**
     * get the version number
     */
    public int getversion()
    {
        return version;
    }
    
    /**
     * return the signature type.
     */
    public int getsignaturetype()
    {
        return signaturetype;
    }
    
    /**
     * return the keyid
     * @return the keyid that created the signature.
     */
    public long getkeyid()
    {
        return keyid;
    }
    
    /**
     * return the signature trailer that must be included with the data
     * to reconstruct the signature
     * 
     * @return byte[]
     */
    public byte[] getsignaturetrailer()
    {
        byte[]    trailer = null;
        
        if (version == 3 || version == 2)
        {
            trailer = new byte[5];
            
            long    time = creationtime / 1000;
            
            trailer[0] = (byte)signaturetype;
            trailer[1] = (byte)(time >> 24);
            trailer[2] = (byte)(time >> 16);
            trailer[3] = (byte)(time >> 8);
            trailer[4] = (byte)(time);
        }
        else
        {
            bytearrayoutputstream    sout = new bytearrayoutputstream();
        
            try
            {
                sout.write((byte)this.getversion());
                sout.write((byte)this.getsignaturetype());
                sout.write((byte)this.getkeyalgorithm());
                sout.write((byte)this.gethashalgorithm());
            
                bytearrayoutputstream    hout = new bytearrayoutputstream();
                signaturesubpacket[]     hashed = this.gethashedsubpackets();
            
                for (int i = 0; i != hashed.length; i++)
                {
                    hashed[i].encode(hout);
                }
                
                byte[]                   data = hout.tobytearray();
            
                sout.write((byte)(data.length >> 8));
                sout.write((byte)data.length);
                sout.write(data);
            
                byte[]    hdata = sout.tobytearray();
            
                sout.write((byte)this.getversion());
                sout.write((byte)0xff);
                sout.write((byte)(hdata.length>> 24));
                sout.write((byte)(hdata.length >> 16));
                sout.write((byte)(hdata.length >> 8));
                sout.write((byte)(hdata.length));
            }
            catch (ioexception e)
            {
                throw new runtimeexception("exception generating trailer: " + e);
            }
                
            trailer = sout.tobytearray();
        }
        
        return trailer;
    }
    
    /**
     * return the encryption algorithm tag
     */
    public int getkeyalgorithm()
    {
        return keyalgorithm;
    }
    
    /**
     * return the hashalgorithm tag
     */
    public int gethashalgorithm()
    {
        return hashalgorithm;
    }
    
    /**
     * return the signature as a set of integers - note this is normalised to be the
     * asn.1 encoding of what appears in the signature packet.
     */
    public mpinteger[] getsignature()
    {
        return signature;
    }

    /**
     * return the byte encoding of the signature section.
     * @return uninterpreted signature bytes.
     */
    public byte[] getsignaturebytes()
    {
        if (signatureencoding == null)
        {
            bytearrayoutputstream bout = new bytearrayoutputstream();
            bcpgoutputstream bcout = new bcpgoutputstream(bout);

            for (int i = 0; i != signature.length; i++)
            {
                try
                {
                    bcout.writeobject(signature[i]);
                }
                catch (ioexception e)
                {
                    throw new runtimeexception("internal error: " + e);
                }
            }
            return bout.tobytearray();
        }
        else
        {
            return arrays.clone(signatureencoding);
        }
    }
    public signaturesubpacket[] gethashedsubpackets()
    {
        return hasheddata;
    }
    
    public signaturesubpacket[] getunhashedsubpackets()
    {
        return unhasheddata;
    }
    
    /**
     * return the creation time of the signature in milli-seconds.
     * 
     * @return the creation time in millis
     */
    public long getcreationtime()
    {
        return creationtime;
    }
    
    public void encode(
        bcpgoutputstream    out)
        throws ioexception
    {
        bytearrayoutputstream    bout = new bytearrayoutputstream();
        bcpgoutputstream         pout = new bcpgoutputstream(bout);
        
        pout.write(version);
        
        if (version == 3 || version == 2)
        {
            pout.write(5); // the length of the next block
            
            long    time = creationtime / 1000;
            
            pout.write(signaturetype);
            pout.write((byte)(time >> 24));
            pout.write((byte)(time >> 16));
            pout.write((byte)(time >> 8));
            pout.write((byte)time);

            pout.write((byte)(keyid >> 56));
            pout.write((byte)(keyid >> 48));
            pout.write((byte)(keyid >> 40));
            pout.write((byte)(keyid >> 32));
            pout.write((byte)(keyid >> 24));
            pout.write((byte)(keyid >> 16));
            pout.write((byte)(keyid >> 8));
            pout.write((byte)(keyid));
            
            pout.write(keyalgorithm);
            pout.write(hashalgorithm);
        }
        else if (version == 4)
        {
            pout.write(signaturetype);
            pout.write(keyalgorithm);
            pout.write(hashalgorithm);
            
            bytearrayoutputstream    sout = new bytearrayoutputstream();
            
            for (int i = 0; i != hasheddata.length; i++)
            {
                hasheddata[i].encode(sout);
            }
            
            byte[]                   data = sout.tobytearray();
    
            pout.write(data.length >> 8);
            pout.write(data.length);
            pout.write(data);
            
            sout.reset();
            
            for (int i = 0; i != unhasheddata.length; i++)
            {
                unhasheddata[i].encode(sout);
            }
            
            data = sout.tobytearray();
      
            pout.write(data.length >> 8);
            pout.write(data.length);
            pout.write(data);
        }
        else
        {
            throw new ioexception("unknown version: " + version);
        }
        
        pout.write(fingerprint);

        if (signature != null)
        {
            for (int i = 0; i != signature.length; i++)
            {
                pout.writeobject(signature[i]);
            }
        }
        else
        {
            pout.write(signatureencoding);
        }

        out.writepacket(signature, bout.tobytearray(), true);
    }

    private void setcreationtime()
    {
        for (int i = 0; i != hasheddata.length; i++)
        {
            if (hasheddata[i] instanceof signaturecreationtime)
            {
                creationtime = ((signaturecreationtime)hasheddata[i]).gettime().gettime();
                break;
            }
        }
    }
}
