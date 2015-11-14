package org.moorecoinlab.crypto.sjcljson;

import org.json.jsonexception;
import org.json.jsonobject;
import org.ripple.bouncycastle.crypto.invalidciphertextexception;
import org.ripple.bouncycastle.crypto.pbeparametersgenerator;
import org.ripple.bouncycastle.crypto.digests.sha256digest;
import org.ripple.bouncycastle.crypto.engines.aesfastengine;
import org.ripple.bouncycastle.crypto.modes.ccmblockcipher;
import org.ripple.bouncycastle.crypto.params.aeadparameters;
import org.ripple.bouncycastle.crypto.params.keyparameter;
import org.ripple.bouncycastle.util.encoders.base64;

import java.io.unsupportedencodingexception;
import java.security.securerandom;
import java.util.arrays;

public class jsonencrypt {
    int ks   = 256;
    int iter = 1000;
    int ts   = 64;
    string mode = "ccm";

    /**
     *  much credit for this class goes to matthew fettig
     *  https://github.com/aurionfinancial/androidwallet/blob/master/src/com/ripple/blobvault.java
     *
     *  this supports ccm mode encrypted data.
     *
     */
    public jsonencrypt(int ks, int iter, int ts) {
        this.ks = ks;
        this.iter = iter;
        this.ts = ts;
    }

    public jsonencrypt() {
    }

    public jsonobject encrypt(string key, jsonobject blob, string adata) {
        jsonobject result = new jsonobject();
        securerandom random = new securerandom();
        byte[] iv = new byte[32],
               salt = new byte[8];

        random.nextbytes(salt);
        random.nextbytes(iv);

        try {
            byte[] plainbytes = blob.tostring().getbytes("utf-8");
            byte[] adatabytes = adata.getbytes("utf8");
            byte[] nonce = computenonce(iv, plainbytes);

            keyparameter keyparam = this.createkey(key, salt, iter, ks);
            aeadparameters ccm = new aeadparameters(
                    keyparam,
                    macsize(ts),
                    nonce,
                    adatabytes);

            ccmblockcipher aes = new ccmblockcipher(new aesfastengine());
            aes.init(true, ccm);

            byte[] enc = new byte[aes.getoutputsize(plainbytes.length)];

            int res = aes.processbytes(
                    plainbytes,
                    0,
                    plainbytes.length,
                    enc,
                    0);

            aes.dofinal(enc, res);

            result.put("ct", base64.encode(enc));
            result.put("iv", base64.encode(iv));
            result.put("salt", base64.encode(salt));
            result.put("adata", encodeadata(adata));
            result.put("mode", mode);
            result.put("ks", ks);
            result.put("iter", iter);
            result.put("ts", ts);
            return result;

        } catch (exception e) {
            throw new runtimeexception(e);
        }
    }



    private int macsize(int ms) {
        return ts;
    }

    public jsonobject decrypt(string key, string json) throws invalidciphertextexception {
        try {
            return decrypt(key, new jsonobject(json));
        } catch (jsonexception e) {
            throw new runtimeexception(e);
        }
    }

    public jsonobject decrypt(string key, jsonobject json) throws invalidciphertextexception {
        try {

            byte[] iv = base64.decode(json.getstring("iv"));
            byte[] ciphertext = base64.decode(json.getstring("ct"));
            byte[] adatabytes = decodeadatabytes(json.getstring("adata"));
            byte[] nonce = computenonce(iv, ciphertext);

            if (!json.getstring("mode").equals("ccm")) {
                throw new runtimeexception("can only decrypt ccm mode encrypted data");
            }

            keyparameter keyparam = this.createkey(
                    key,
                    base64.decode(json.getstring("salt")),
                    json.getint("iter"),
                    json.getint("ks"));

            aeadparameters ccm = new aeadparameters(
                    keyparam,
                    macsize(json.getint("ts")),
                    nonce,
                    adatabytes);

            ccmblockcipher aes = new ccmblockcipher(new aesfastengine());
            aes.init(false, ccm);

            byte[] plainbytes = new byte[aes.getoutputsize(ciphertext.length)];

            int res = aes.processbytes(
                    ciphertext,
                    0,
                    ciphertext.length,
                    plainbytes,
                    0);

            aes.dofinal(plainbytes, res);
            string text = new string(plainbytes, "utf-8");
            return new jsonobject(text);
        } catch (invalidciphertextexception e ) {
            throw e;
        } catch (exception e) {
            throw new runtimeexception(e);
        }
    }

    private string encodeadata(string adata) {
        return jsescape.escape(adata);
    }

    private byte[] decodeadatabytes(string adata) {
        try {
            return jsescape.unescape(adata).getbytes("utf8");
        } catch (unsupportedencodingexception e) {
            throw new runtimeexception(e);
        }
    }

    private keyparameter createkey(string password, byte[] salt, int iterations, int keysizeinbits) {
        pkcs5s2parametersgenerator generator = new pkcs5s2parametersgenerator(new sha256digest());
        generator.init(pbeparametersgenerator.pkcs5passwordtoutf8bytes(password.tochararray()),
                       salt,
                       iterations);
        return (keyparameter) generator.generatederivedmacparameters(keysizeinbits);
    }

    private byte[] computenonce(byte[] iv, byte[] plainbytes) {
        int ivl = iv.length;
        int ol = plainbytes.length  - (ts / 8);
        int l =2;
        while (l <4 && (ol >>> 8* l) != 0) l++;
        if (l < 15 - ivl) { l = 15-ivl; }
        int newlength = 15 - l;
        return arrays.copyof(iv, newlength);
    }
}
