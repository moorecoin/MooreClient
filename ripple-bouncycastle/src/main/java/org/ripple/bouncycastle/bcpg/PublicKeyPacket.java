package org.ripple.bouncycastle.bcpg;

import java.io.*;
import java.util.date;

/**
 * basic packet for a pgp public key
 */
public class publickeypacket 
    extends containedpacket implements publickeyalgorithmtags
{
    private int            version;
    private long           time;
    private int            validdays;
    private int            algorithm;
    private bcpgkey        key;
    
    publickeypacket(
        bcpginputstream    in)
        throws ioexception
    {      
        version = in.read();
        time = ((long)in.read() << 24) | (in.read() << 16) | (in.read() << 8) | in.read();
 
        if (version <= 3)
        {
            validdays = (in.read() << 8) | in.read();
        }
        
        algorithm = (byte)in.read();

        switch (algorithm)
        {
        case rsa_encrypt:
        case rsa_general:
        case rsa_sign:
            key = new rsapublicbcpgkey(in);
            break;
        case dsa:
            key = new dsapublicbcpgkey(in);
            break;
        case elgamal_encrypt:
        case elgamal_general:
            key = new elgamalpublicbcpgkey(in);
            break;
        default:
            throw new ioexception("unknown pgp public key algorithm encountered");
        }
    }
    
    /**
     * construct version 4 public key packet.
     * 
     * @param algorithm
     * @param time
     * @param key
     */
    public publickeypacket(
        int        algorithm,
        date       time,
        bcpgkey    key)
    {
        this.version = 4;
        this.time = time.gettime() / 1000;
        this.algorithm = algorithm;
        this.key = key;
    }
    
    public int getversion()
    {
        return version;
    }
    
    public int getalgorithm()
    {
        return algorithm;
    }
    
    public int getvaliddays()
    {
        return validdays;
    }
    
    public date gettime()
    {
        return new date(time * 1000);
    }
    
    public bcpgkey getkey()
    {
        return key;
    }
    
    public byte[] getencodedcontents() 
        throws ioexception
    {
        bytearrayoutputstream    bout = new bytearrayoutputstream();
        bcpgoutputstream         pout = new bcpgoutputstream(bout);
    
        pout.write(version);
    
        pout.write((byte)(time >> 24));
        pout.write((byte)(time >> 16));
        pout.write((byte)(time >> 8));
        pout.write((byte)time);
    
        if (version <= 3)
        {
            pout.write((byte)(validdays >> 8));
            pout.write((byte)validdays);
        }
    
        pout.write(algorithm);
    
        pout.writeobject((bcpgobject)key);
    
        return bout.tobytearray();
    }
    
    public void encode(
        bcpgoutputstream    out)
        throws ioexception
    {
        out.writepacket(public_key, getencodedcontents(), true);
    }
}
