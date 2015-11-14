package org.ripple.bouncycastle.bcpg;

import java.io.*;
import java.math.biginteger;

/**
 * basic packet for a pgp public key
 */
public class publickeyencsessionpacket 
    extends containedpacket implements publickeyalgorithmtags
{
    private int            version;
    private long           keyid;
    private int            algorithm;
    private biginteger[]   data;
    
    publickeyencsessionpacket(
        bcpginputstream    in)
        throws ioexception
    {      
        version = in.read();
        
        keyid |= (long)in.read() << 56;
        keyid |= (long)in.read() << 48;
        keyid |= (long)in.read() << 40;
        keyid |= (long)in.read() << 32;
        keyid |= (long)in.read() << 24;
        keyid |= (long)in.read() << 16;
        keyid |= (long)in.read() << 8;
        keyid |= in.read();
        
        algorithm = in.read();
        
        switch (algorithm)
        {
        case rsa_encrypt:
        case rsa_general:
            data = new biginteger[1];
            
            data[0] = new mpinteger(in).getvalue();
            break;
        case elgamal_encrypt:
        case elgamal_general:
            data = new biginteger[2];
            
            data[0] = new mpinteger(in).getvalue();
            data[1] = new mpinteger(in).getvalue();
            break;
        default:
            throw new ioexception("unknown pgp public key algorithm encountered");
        }
    }
    
    public publickeyencsessionpacket(
        long           keyid,
        int            algorithm,
        biginteger[]   data)
    {
        this.version = 3;
        this.keyid = keyid;
        this.algorithm = algorithm;
        this.data = data;
    }
    
    public int getversion()
    {
        return version;
    }
    
    public long getkeyid()
    {
        return keyid;
    }
    
    public int getalgorithm()
    {
        return algorithm;
    }
    
    public biginteger[] getencsessionkey()
    {
        return data;
    }
    
    public void encode(
        bcpgoutputstream    out)
        throws ioexception
    {
        bytearrayoutputstream  bout = new bytearrayoutputstream();
        bcpgoutputstream       pout = new bcpgoutputstream(bout);
  
          pout.write(version);
          
        pout.write((byte)(keyid >> 56));
        pout.write((byte)(keyid >> 48));
        pout.write((byte)(keyid >> 40));
        pout.write((byte)(keyid >> 32));
        pout.write((byte)(keyid >> 24));
        pout.write((byte)(keyid >> 16));
        pout.write((byte)(keyid >> 8));
        pout.write((byte)(keyid));
        
        pout.write(algorithm);
        
        for (int i = 0; i != data.length; i++)
        {
            pout.writeobject(new mpinteger(data[i]));
        }
        
        out.writepacket(public_key_enc_session , bout.tobytearray(), true);
    }
}
