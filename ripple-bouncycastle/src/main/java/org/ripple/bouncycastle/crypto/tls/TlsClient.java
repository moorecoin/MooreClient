package org.ripple.bouncycastle.crypto.tls;

import java.io.ioexception;
import java.util.hashtable;
import java.util.vector;

public interface tlsclient
    extends tlspeer
{

    void init(tlsclientcontext context);

    protocolversion getclienthellorecordlayerversion();

    protocolversion getclientversion();

    int[] getciphersuites();

    short[] getcompressionmethods();

    // hashtable is (integer -> byte[])
    hashtable getclientextensions()
        throws ioexception;

    void notifyserverversion(protocolversion selectedversion)
        throws ioexception;

    void notifysessionid(byte[] sessionid);

    void notifyselectedciphersuite(int selectedciphersuite);

    void notifyselectedcompressionmethod(short selectedcompressionmethod);

    void notifysecurerenegotiation(boolean securenegotiation)
        throws ioexception;

    // hashtable is (integer -> byte[])
    void processserverextensions(hashtable serverextensions)
        throws ioexception;

    // vector is (supplementaldataentry)
    void processserversupplementaldata(vector serversupplementaldata)
        throws ioexception;

    tlskeyexchange getkeyexchange()
        throws ioexception;

    tlsauthentication getauthentication()
        throws ioexception;

    // vector is (supplementaldataentry)
    vector getclientsupplementaldata()
        throws ioexception;

    tlscompression getcompression()
        throws ioexception;

    tlscipher getcipher()
        throws ioexception;

    /**
     * rfc 5077 3.3. newsessionticket handshake message
     * <p/>
     * this method will be called (only) when a newsessionticket handshake message is received. the
     * ticket is opaque to the client and clients must not examine the ticket under the assumption
     * that it complies with e.g. <i>rfc 5077 4. recommended ticket construction</i>.
     *
     * @param newsessionticket the ticket.
     * @throws ioexception
     */
    void notifynewsessionticket(newsessionticket newsessionticket)
        throws ioexception;

    void notifyhandshakecomplete()
        throws ioexception;
}
