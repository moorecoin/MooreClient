package org.moorecoinlab.crypto;


import org.ripple.bouncycastle.util.encoders.hex;

import javax.crypto.mac;
import javax.crypto.secretkey;
import javax.crypto.spec.secretkeyspec;
import java.io.unsupportedencodingexception;
import java.security.invalidkeyexception;
import java.security.messagedigest;
import java.security.nosuchalgorithmexception;
import java.util.random;

public class hmac {
    public static string getsalt(){
        byte[] b = new byte[128];
        new random().nextbytes(b);
        messagedigest digest = null;
        try {
            digest = messagedigest.getinstance("sha-256");
        } catch (nosuchalgorithmexception e) {
            e.printstacktrace();
        }
        digest.update(b);
        byte[] res = digest.digest();
        system.out.println(new string(hex.encode(res)));
        return new string(hex.encode(res));
    }

    public static string getsaltpassword(string salt, string password){
        try {
            mac mac = mac.getinstance("hmacsha256");
            //get the bytes of the hmac key and data string
            byte[] secretbyte = salt.getbytes("utf-8");
            byte[] databytes = password.getbytes("utf-8");
            secretkey secret = new secretkeyspec(secretbyte, "sha256");
            mac.init(secret);
            mac.update(databytes);
            byte[] dofinal = mac.dofinal();
            byte[] hexb = new hex().encode(dofinal);
            string checksum = new string(hexb);
            return checksum;
        } catch (nosuchalgorithmexception e) {
            e.printstacktrace();
        } catch (invalidkeyexception e) {
            e.printstacktrace();
        } catch (unsupportedencodingexception e) {
            e.printstacktrace();
        }
        return null;
    }

}
