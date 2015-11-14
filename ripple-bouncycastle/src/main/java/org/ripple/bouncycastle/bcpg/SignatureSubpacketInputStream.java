package org.ripple.bouncycastle.bcpg;

import org.ripple.bouncycastle.bcpg.sig.exportable;
import org.ripple.bouncycastle.bcpg.sig.issuerkeyid;
import org.ripple.bouncycastle.bcpg.sig.keyexpirationtime;
import org.ripple.bouncycastle.bcpg.sig.keyflags;
import org.ripple.bouncycastle.bcpg.sig.notationdata;
import org.ripple.bouncycastle.bcpg.sig.preferredalgorithms;
import org.ripple.bouncycastle.bcpg.sig.primaryuserid;
import org.ripple.bouncycastle.bcpg.sig.revocable;
import org.ripple.bouncycastle.bcpg.sig.signaturecreationtime;
import org.ripple.bouncycastle.bcpg.sig.signatureexpirationtime;
import org.ripple.bouncycastle.bcpg.sig.signeruserid;
import org.ripple.bouncycastle.bcpg.sig.trustsignature;
import org.ripple.bouncycastle.util.io.streams;

import java.io.eofexception;
import java.io.ioexception;
import java.io.inputstream;

/**
 * reader for signature sub-packets
 */
public class signaturesubpacketinputstream
    extends inputstream implements signaturesubpackettags
{
    inputstream    in;
    
    public signaturesubpacketinputstream(
        inputstream    in)
    {
        this.in = in;
    }
    
    public int available()
        throws ioexception
    {
        return in.available();
    }
    
    public int read()
        throws ioexception
    {
        return in.read();
    }

    public signaturesubpacket readpacket()
        throws ioexception
    {
        int            l = this.read();
        int            bodylen = 0;
        
        if (l < 0)
        {
            return null;
        }

        if (l < 192)
        {
            bodylen = l;
        }
        else if (l <= 223)
        {
            bodylen = ((l - 192) << 8) + (in.read()) + 192;
        }
        else if (l == 255)
        {
            bodylen = (in.read() << 24) | (in.read() << 16) |  (in.read() << 8)  | in.read();
        }
        else
        {
            // todo error?
        }

        int        tag = in.read();

        if (tag < 0)
        {
               throw new eofexception("unexpected eof reading signature sub packet");
        }
       
        byte[]    data = new byte[bodylen - 1];
        if (streams.readfully(in, data) < data.length)
        {
            throw new eofexception();
        }
       
        boolean   iscritical = ((tag & 0x80) != 0);
        int       type = tag & 0x7f;

        switch (type)
        {
        case creation_time:
            return new signaturecreationtime(iscritical, data);
        case key_expire_time:
            return new keyexpirationtime(iscritical, data);
        case expire_time:
            return new signatureexpirationtime(iscritical, data);
        case revocable:
            return new revocable(iscritical, data);
        case exportable:
            return new exportable(iscritical, data);
        case issuer_key_id:
            return new issuerkeyid(iscritical, data);
        case trust_sig:
            return new trustsignature(iscritical, data);
        case preferred_comp_algs:
        case preferred_hash_algs:
        case preferred_sym_algs:
            return new preferredalgorithms(type, iscritical, data);
        case key_flags:
            return new keyflags(iscritical, data);
        case primary_user_id:
            return new primaryuserid(iscritical, data);
        case signer_user_id:
            return new signeruserid(iscritical, data);
        case notation_data:
            return new notationdata(iscritical, data);
        }

        return new signaturesubpacket(type, iscritical, data);
    }
}
