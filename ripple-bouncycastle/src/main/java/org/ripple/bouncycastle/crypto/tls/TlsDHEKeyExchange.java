package org.ripple.bouncycastle.crypto.tls;

import java.io.bytearrayoutputstream;
import java.io.ioexception;
import java.io.inputstream;
import java.math.biginteger;
import java.util.vector;

import org.ripple.bouncycastle.crypto.asymmetriccipherkeypair;
import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.crypto.signer;
import org.ripple.bouncycastle.crypto.generators.dhkeypairgenerator;
import org.ripple.bouncycastle.crypto.io.signerinputstream;
import org.ripple.bouncycastle.crypto.params.dhkeygenerationparameters;
import org.ripple.bouncycastle.crypto.params.dhparameters;
import org.ripple.bouncycastle.crypto.params.dhpublickeyparameters;

public class tlsdhekeyexchange
    extends tlsdhkeyexchange
{

    protected tlssignercredentials servercredentials = null;

    public tlsdhekeyexchange(int keyexchange, vector supportedsignaturealgorithms, dhparameters dhparameters)
    {
        super(keyexchange, supportedsignaturealgorithms, dhparameters);
    }

    public void processservercredentials(tlscredentials servercredentials)
        throws ioexception
    {

        if (!(servercredentials instanceof tlssignercredentials))
        {
            throw new tlsfatalalert(alertdescription.internal_error);
        }

        processservercertificate(servercredentials.getcertificate());

        this.servercredentials = (tlssignercredentials)servercredentials;
    }

    public byte[] generateserverkeyexchange()
        throws ioexception
    {

        if (this.dhparameters == null)
        {
            throw new tlsfatalalert(alertdescription.internal_error);
        }

        bytearrayoutputstream buf = new bytearrayoutputstream();

        dhkeypairgenerator kpg = new dhkeypairgenerator();
        kpg.init(new dhkeygenerationparameters(context.getsecurerandom(), this.dhparameters));
        asymmetriccipherkeypair kp = kpg.generatekeypair();

        biginteger ys = ((dhpublickeyparameters)kp.getpublic()).gety();

        tlsdhutils.writedhparameter(dhparameters.getp(), buf);
        tlsdhutils.writedhparameter(dhparameters.getg(), buf);
        tlsdhutils.writedhparameter(ys, buf);

        byte[] digestinput = buf.tobytearray();

        digest d = new combinedhash();
        securityparameters securityparameters = context.getsecurityparameters();
        d.update(securityparameters.clientrandom, 0, securityparameters.clientrandom.length);
        d.update(securityparameters.serverrandom, 0, securityparameters.serverrandom.length);
        d.update(digestinput, 0, digestinput.length);

        byte[] hash = new byte[d.getdigestsize()];
        d.dofinal(hash, 0);

        byte[] sigbytes = servercredentials.generatecertificatesignature(hash);
        /*
         * todo rfc 5246 4.7. digitally-signed element needs signatureandhashalgorithm prepended from tls 1.2
         */
        tlsutils.writeopaque16(sigbytes, buf);

        return buf.tobytearray();
    }

    public void processserverkeyexchange(inputstream input)
        throws ioexception
    {

        securityparameters securityparameters = context.getsecurityparameters();

        signer signer = initverifyer(tlssigner, securityparameters);
        inputstream sigin = new signerinputstream(input, signer);

        biginteger p = tlsdhutils.readdhparameter(sigin);
        biginteger g = tlsdhutils.readdhparameter(sigin);
        biginteger ys = tlsdhutils.readdhparameter(sigin);

        byte[] sigbytes = tlsutils.readopaque16(input);
        if (!signer.verifysignature(sigbytes))
        {
            throw new tlsfatalalert(alertdescription.decrypt_error);
        }

        this.dhagreeserverpublickey = validatedhpublickey(new dhpublickeyparameters(ys, new dhparameters(p, g)));
    }

    protected signer initverifyer(tlssigner tlssigner, securityparameters securityparameters)
    {
        signer signer = tlssigner.createverifyer(this.serverpublickey);
        signer.update(securityparameters.clientrandom, 0, securityparameters.clientrandom.length);
        signer.update(securityparameters.serverrandom, 0, securityparameters.serverrandom.length);
        return signer;
    }
}
