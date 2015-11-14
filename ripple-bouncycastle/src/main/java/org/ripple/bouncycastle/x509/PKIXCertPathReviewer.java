package org.ripple.bouncycastle.x509;

import java.io.bytearrayinputstream;
import java.io.ioexception;
import java.math.biginteger;
import java.net.httpurlconnection;
import java.net.inetaddress;
import java.net.url;
import java.security.generalsecurityexception;
import java.security.publickey;
import java.security.signatureexception;
import java.security.cert.certpath;
import java.security.cert.certpathvalidatorexception;
import java.security.cert.certificateexpiredexception;
import java.security.cert.certificatefactory;
import java.security.cert.certificatenotyetvalidexception;
import java.security.cert.pkixcertpathchecker;
import java.security.cert.pkixparameters;
import java.security.cert.policynode;
import java.security.cert.trustanchor;
import java.security.cert.x509crl;
import java.security.cert.x509crlentry;
import java.security.cert.x509certselector;
import java.security.cert.x509certificate;
import java.util.arraylist;
import java.util.collection;
import java.util.date;
import java.util.enumeration;
import java.util.hashmap;
import java.util.hashset;
import java.util.iterator;
import java.util.list;
import java.util.map;
import java.util.set;
import java.util.vector;

import javax.security.auth.x500.x500principal;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1inputstream;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.derenumerated;
import org.ripple.bouncycastle.asn1.deria5string;
import org.ripple.bouncycastle.asn1.derinteger;
import org.ripple.bouncycastle.asn1.derobjectidentifier;
import org.ripple.bouncycastle.asn1.deroctetstring;
import org.ripple.bouncycastle.asn1.x509.accessdescription;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;
import org.ripple.bouncycastle.asn1.x509.authorityinformationaccess;
import org.ripple.bouncycastle.asn1.x509.authoritykeyidentifier;
import org.ripple.bouncycastle.asn1.x509.basicconstraints;
import org.ripple.bouncycastle.asn1.x509.crldistpoint;
import org.ripple.bouncycastle.asn1.x509.distributionpoint;
import org.ripple.bouncycastle.asn1.x509.distributionpointname;
import org.ripple.bouncycastle.asn1.x509.generalname;
import org.ripple.bouncycastle.asn1.x509.generalnames;
import org.ripple.bouncycastle.asn1.x509.generalsubtree;
import org.ripple.bouncycastle.asn1.x509.issuingdistributionpoint;
import org.ripple.bouncycastle.asn1.x509.nameconstraints;
import org.ripple.bouncycastle.asn1.x509.policyinformation;
import org.ripple.bouncycastle.asn1.x509.x509extensions;
import org.ripple.bouncycastle.asn1.x509.qualified.iso4217currencycode;
import org.ripple.bouncycastle.asn1.x509.qualified.monetaryvalue;
import org.ripple.bouncycastle.asn1.x509.qualified.qcstatement;
import org.ripple.bouncycastle.i18n.errorbundle;
import org.ripple.bouncycastle.i18n.localestring;
import org.ripple.bouncycastle.i18n.filter.trustedinput;
import org.ripple.bouncycastle.i18n.filter.untrustedinput;
import org.ripple.bouncycastle.i18n.filter.untrustedurlinput;
import org.ripple.bouncycastle.jce.provider.annotatedexception;
import org.ripple.bouncycastle.jce.provider.certpathvalidatorutilities;
import org.ripple.bouncycastle.jce.provider.pkixnameconstraintvalidator;
import org.ripple.bouncycastle.jce.provider.pkixnameconstraintvalidatorexception;
import org.ripple.bouncycastle.jce.provider.pkixpolicynode;
import org.ripple.bouncycastle.util.integers;
import org.ripple.bouncycastle.x509.extension.x509extensionutil;

/**
 * pkixcertpathreviewer<br>
 * validation of x.509 certificate paths. tries to find as much errors in the path as possible.
 */
public class pkixcertpathreviewer extends certpathvalidatorutilities
{
    
    private static final string qc_statement = x509extensions.qcstatements.getid();
    private static final string crl_dist_points = x509extensions.crldistributionpoints.getid();
    private static final string auth_info_access = x509extensions.authorityinfoaccess.getid();
    
    private static final string resource_name = "org.bouncycastle.x509.certpathreviewermessages";
    
    // input parameters
    
    protected certpath certpath;

    protected pkixparameters pkixparams;

    protected date validdate;

    // state variables
    
    protected list certs;

    protected int n;
    
    // output variables
    
    protected list[] notifications;
    protected list[] errors;
    protected trustanchor trustanchor;
    protected publickey subjectpublickey;
    protected policynode policytree;
    
    private boolean initialized;
    
    /** 
     * initializes the pkixcertpathreviewer with the given {@link certpath} and {@link pkixparameters} params
     * @param certpath the {@link certpath} to validate
     * @param params the {@link pkixparameters} to use
     * @throws certpathreviewerexception if the certpath is empty
     * @throws illegalstateexception if the {@link pkixcertpathreviewer} is already initialized
     */
    public void init(certpath certpath, pkixparameters params)
            throws certpathreviewerexception
    {
        if (initialized)
        {
            throw new illegalstateexception("object is already initialized!");
        }
        initialized = true;
        
        // check input parameters
        if (certpath == null)
        {
            throw new nullpointerexception("certpath was null");
        }
        this.certpath = certpath;

        certs = certpath.getcertificates();
        n = certs.size();
        if (certs.isempty())
        {
            throw new certpathreviewerexception(
                    new errorbundle(resource_name,"certpathreviewer.emptycertpath"));
        }

        pkixparams = (pkixparameters) params.clone();

        // 6.1.1 - inputs

        // a) done

        // b)

        validdate = getvaliddate(pkixparams);

        // c) part of pkixparams

        // d) done at the beginning of checksignatures

        // e) f) g) part of pkixparams
        
        // initialize output parameters
        
        notifications = null;
        errors = null;
        trustanchor = null;
        subjectpublickey = null;
        policytree = null;
    }
    
    /**
     * creates a pkixcertpathreviewer and initializes it with the given {@link certpath} and {@link pkixparameters} params
     * @param certpath the {@link certpath} to validate
     * @param params the {@link pkixparameters} to use
     * @throws certpathreviewerexception if the certpath is empty
     */
    public pkixcertpathreviewer(certpath certpath, pkixparameters params)
            throws certpathreviewerexception
    {
        init(certpath, params);
    }
    
    /**
     * creates an empty pkixcertpathreviewer. don't forget to call init() to initialize the object.
     */
    public pkixcertpathreviewer()
    {
        // do nothing
    }
    
    /**
     * 
     * @return the certpath that was validated
     */
    public certpath getcertpath()
    {
        return certpath;
    }
    
    /**
     * 
     * @return the size of the certpath
     */
    public int getcertpathsize()
    {
        return n;
    }

    /**
     * returns an array of lists which contains a list of global error messages 
     * and a list of error messages for each certificate in the path.
     * the global error list is at index 0. the error lists for each certificate at index 1 to n. 
     * the error messages are of type.
     * @return the array of lists which contain the error messages
     * @throws illegalstateexception if the {@link pkixcertpathreviewer} was not initialized
     */
    public list[] geterrors()
    {
        dochecks();
        return errors;
    }
    
    /**
     * returns an list of error messages for the certificate at the given index in the certpath.
     * if index == -1 then the list of global errors is returned with errors not specific to a certificate. 
     * @param index the index of the certificate in the certpath
     * @return list of error messages for the certificate
     * @throws illegalstateexception if the {@link pkixcertpathreviewer} was not initialized
     */
    public list geterrors(int index)
    {
        dochecks();
        return errors[index + 1];
    }

    /**
     * returns an array of lists which contains a list of global notification messages 
     * and a list of botification messages for each certificate in the path.
     * the global notificatio list is at index 0. the notification lists for each certificate at index 1 to n. 
     * the error messages are of type.
     * @return the array of lists which contain the notification messages
     * @throws illegalstateexception if the {@link pkixcertpathreviewer} was not initialized
     */
    public list[] getnotifications()
    {
        dochecks();
        return notifications;
    }
    
    /**
     * returns an list of notification messages for the certificate at the given index in the certpath.
     * if index == -1 then the list of global notifications is returned with notifications not specific to a certificate. 
     * @param index the index of the certificate in the certpath
     * @return list of notification messages for the certificate
     * @throws illegalstateexception if the {@link pkixcertpathreviewer} was not initialized
     */
    public list getnotifications(int index)
    {
        dochecks();
        return notifications[index + 1];
    }

    /**
     * 
     * @return the valid policy tree, <b>null</b> if no valid policy exists.
     * @throws illegalstateexception if the {@link pkixcertpathreviewer} was not initialized
     */
    public policynode getpolicytree()
    {
        dochecks();
        return policytree;
    }

    /**
     * 
     * @return the publickey if the last certificate in the certpath
     * @throws illegalstateexception if the {@link pkixcertpathreviewer} was not initialized
     */
    public publickey getsubjectpublickey()
    {
        dochecks();
        return subjectpublickey;
    }

    /**
     * 
     * @return the trustanchor for the certpath, <b>null</b> if no valid trustanchor was found.
     * @throws illegalstateexception if the {@link pkixcertpathreviewer} was not initialized
     */
    public trustanchor gettrustanchor()
    {
        dochecks();
        return trustanchor;
    }
    
    /**
     * 
     * @return if the certpath is valid
     * @throws illegalstateexception if the {@link pkixcertpathreviewer} was not initialized
     */
    public boolean isvalidcertpath()
    {
        dochecks();
        boolean valid = true;
        for (int i = 0; i < errors.length; i++)
        {
            if (!errors[i].isempty())
            {
                valid = false;
                break;
            }
        }
        return valid;
    }
    
    protected void addnotification(errorbundle msg)
    {
        notifications[0].add(msg);
    }
    
    protected void addnotification(errorbundle msg, int index)
    {
        if (index < -1 || index >= n)
        {
            throw new indexoutofboundsexception();
        }
        notifications[index + 1].add(msg);
    }

    protected void adderror(errorbundle msg) 
    {
        errors[0].add(msg);
    }
    
    protected void adderror(errorbundle msg, int index)
    {
        if (index < -1 || index >= n)
        {
            throw new indexoutofboundsexception();
        }
        errors[index + 1].add(msg);
    }
    
    protected void dochecks()
    {
        if (!initialized)
        {
            throw new illegalstateexception("object not initialized. call init() first.");
        }
        if (notifications == null)
        {
            // initialize lists
            notifications = new list[n+1];
            errors = new list[n+1];
            
            for (int i = 0; i < notifications.length; i++)
            {
                notifications[i] = new arraylist();
                errors[i] = new arraylist();
            }
            
            // check signatures
            checksignatures();
            
            // check name constraints
            checknameconstraints();
            
            // check path length
            checkpathlength();
            
            // check policy
            checkpolicy();
            
            // check other critical extensions
            checkcriticalextensions();
            
        }
    }

    private void checknameconstraints()
    {
        x509certificate cert = null;
        
        //
        // setup
        //
        
        // (b)  and (c)
        pkixnameconstraintvalidator nameconstraintvalidator = new pkixnameconstraintvalidator();

        //
        // process each certificate except the last in the path
        //
        int index;
        int i;
        
        try 
        {
            for (index = certs.size()-1; index>0; index--) 
            {
                i = n - index;
                
                //
                // certificate processing
                //    
                
                cert = (x509certificate) certs.get(index);
                
                // b),c)
                
                if (!isselfissued(cert))
                {
                    x500principal principal = getsubjectprincipal(cert);
                    asn1inputstream ain = new asn1inputstream(new bytearrayinputstream(principal.getencoded()));
                    asn1sequence    dns;
    
                    try
                    {
                        dns = (asn1sequence)ain.readobject();
                    }
                    catch (ioexception e)
                    {
                        errorbundle msg = new errorbundle(resource_name,"certpathreviewer.ncsubjectnameerror", 
                                new object[] {new untrustedinput(principal)});
                        throw new certpathreviewerexception(msg,e,certpath,index);
                    }
    
                    try
                    {
                        nameconstraintvalidator.checkpermitteddn(dns);
                    }
                    catch (pkixnameconstraintvalidatorexception cpve)
                    {
                        errorbundle msg = new errorbundle(resource_name,"certpathreviewer.notpermitteddn", 
                                new object[] {new untrustedinput(principal.getname())});
                        throw new certpathreviewerexception(msg,cpve,certpath,index);
                    }
                    
                    try
                    {
                        nameconstraintvalidator.checkexcludeddn(dns);
                    }
                    catch (pkixnameconstraintvalidatorexception cpve)
                    {
                        errorbundle msg = new errorbundle(resource_name,"certpathreviewer.excludeddn",
                                new object[] {new untrustedinput(principal.getname())});
                        throw new certpathreviewerexception(msg,cpve,certpath,index);
                    }
            
                    asn1sequence altname;
                    try 
                    {
                        altname = (asn1sequence)getextensionvalue(cert, subject_alternative_name);
                    }
                    catch (annotatedexception ae)
                    {
                        errorbundle msg = new errorbundle(resource_name,"certpathreviewer.subjaltnameexterror");
                        throw new certpathreviewerexception(msg,ae,certpath,index);
                    }
                    
                    if (altname != null)
                    {
                        for (int j = 0; j < altname.size(); j++)
                        {
                            generalname name = generalname.getinstance(altname.getobjectat(j));

                            try
                            {
                                nameconstraintvalidator.checkpermitted(name);
                                nameconstraintvalidator.checkexcluded(name);
                            }
                            catch (pkixnameconstraintvalidatorexception cpve)
                            {
                                errorbundle msg = new errorbundle(resource_name,"certpathreviewer.notpermittedemail",
                                        new object[] {new untrustedinput(name)});
                                throw new certpathreviewerexception(msg,cpve,certpath,index);
                            }
//                            switch(o.gettagno())            todo - move resources to pkixnameconstraints
//                            {
//                            case 1:
//                                string email = deria5string.getinstance(o, true).getstring();
//
//                                try
//                                {
//                                    checkpermittedemail(permittedsubtreesemail, email);
//                                }
//                                catch (certpathvalidatorexception cpve)
//                                {
//                                    errorbundle msg = new errorbundle(resource_name,"certpathreviewer.notpermittedemail",
//                                            new object[] {new untrustedinput(email)});
//                                    throw new certpathreviewerexception(msg,cpve,certpath,index);
//                                }
//
//                                try
//                                {
//                                    checkexcludedemail(excludedsubtreesemail, email);
//                                }
//                                catch (certpathvalidatorexception cpve)
//                                {
//                                    errorbundle msg = new errorbundle(resource_name,"certpathreviewer.excludedemail",
//                                            new object[] {new untrustedinput(email)});
//                                    throw new certpathreviewerexception(msg,cpve,certpath,index);
//                                }
//
//                                break;
//                            case 4:
//                                asn1sequence altdn = asn1sequence.getinstance(o, true);
//
//                                try
//                                {
//                                    checkpermitteddn(permittedsubtreesdn, altdn);
//                                }
//                                catch (certpathvalidatorexception cpve)
//                                {
//                                    x509name altdnname = new x509name(altdn);
//                                    errorbundle msg = new errorbundle(resource_name,"certpathreviewer.notpermitteddn",
//                                            new object[] {new untrustedinput(altdnname)});
//                                    throw new certpathreviewerexception(msg,cpve,certpath,index);
//                                }
//
//                                try
//                                {
//                                    checkexcludeddn(excludedsubtreesdn, altdn);
//                                }
//                                catch (certpathvalidatorexception cpve)
//                                {
//                                    x509name altdnname = new x509name(altdn);
//                                    errorbundle msg = new errorbundle(resource_name,"certpathreviewer.excludeddn",
//                                            new object[] {new untrustedinput(altdnname)});
//                                    throw new certpathreviewerexception(msg,cpve,certpath,index);
//                                }
//
//                                break;
//                            case 7:
//                                byte[] ip = asn1octetstring.getinstance(o, true).getoctets();
//
//                                try
//                                {
//                                    checkpermittedip(permittedsubtreesip, ip);
//                                }
//                                catch (certpathvalidatorexception cpve)
//                                {
//                                    errorbundle msg = new errorbundle(resource_name,"certpathreviewer.notpermittedip",
//                                            new object[] {iptostring(ip)});
//                                    throw new certpathreviewerexception(msg,cpve,certpath,index);
//                                }
//
//                                try
//                                {
//                                    checkexcludedip(excludedsubtreesip, ip);
//                                }
//                                catch (certpathvalidatorexception cpve)
//                                {
//                                    errorbundle msg = new errorbundle(resource_name,"certpathreviewer.excludedip",
//                                            new object[] {iptostring(ip)});
//                                    throw new certpathreviewerexception(msg,cpve,certpath,index);
//                                }
//                            }
                        }
                    }
                }
                
                //
                // prepare for next certificate
                //
                
                //
                // (g) handle the name constraints extension
                //
                asn1sequence ncseq;
                try 
                {
                    ncseq = (asn1sequence)getextensionvalue(cert, name_constraints);
                }
                catch (annotatedexception ae)
                {
                    errorbundle msg = new errorbundle(resource_name,"certpathreviewer.ncexterror");
                    throw new certpathreviewerexception(msg,ae,certpath,index);
                }
                
                if (ncseq != null)
                {
                    nameconstraints nc = nameconstraints.getinstance(ncseq);

                    //
                    // (g) (1) permitted subtrees
                    //
                    generalsubtree[] permitted = nc.getpermittedsubtrees();
                    if (permitted != null)
                    {
                        nameconstraintvalidator.intersectpermittedsubtree(permitted);
                    }
                
                    //
                    // (g) (2) excluded subtrees
                    //
                    generalsubtree[] excluded = nc.getexcludedsubtrees();
                    if (excluded != null)
                    {
                        for (int c = 0; c != excluded.length; c++)
                        {
                             nameconstraintvalidator.addexcludedsubtree(excluded[c]);
                        }
                    }
                }
                
            } // for
        }
        catch (certpathreviewerexception cpre)
        {
            adderror(cpre.geterrormessage(),cpre.getindex());
        }
        
    }

    /*
     * checks: - path length constraints and reports - total path length
     */
    private void checkpathlength()
    {
        // init
        int maxpathlength = n;
        int totalpathlength = 0;

        x509certificate cert = null;

        int i;
        for (int index = certs.size() - 1; index > 0; index--)
        {
            i = n - index;

            cert = (x509certificate) certs.get(index);

            // l)

            if (!isselfissued(cert))
            {
                if (maxpathlength <= 0)
                {
                    errorbundle msg = new errorbundle(resource_name,"certpathreviewer.pathlenghtextended");
                    adderror(msg);
                }
                maxpathlength--;
                totalpathlength++;
            }

            // m)

            basicconstraints bc;
            try
            {
                bc = basicconstraints.getinstance(getextensionvalue(cert,
                        basic_constraints));
            }
            catch (annotatedexception ae)
            {
                errorbundle msg = new errorbundle(resource_name,"certpathreviewer.processlengthconsterror");
                adderror(msg,index);
                bc = null;
            }

            if (bc != null)
            {
                biginteger _pathlengthconstraint = bc.getpathlenconstraint();

                if (_pathlengthconstraint != null)
                {
                    int _plc = _pathlengthconstraint.intvalue();

                    if (_plc < maxpathlength)
                    {
                        maxpathlength = _plc;
                    }
                }
            }

        }

        errorbundle msg = new errorbundle(resource_name,"certpathreviewer.totalpathlength",
                new object[]{integers.valueof(totalpathlength)});
        
        addnotification(msg);
    }

    /*
     * checks: - signatures - name chaining - validity of certificates - todo:
     * if certificate revoked (if specified in the parameters)
     */
    private void checksignatures()
    {
        // 1.6.1 - inputs
        
        // d)
        
        trustanchor trust = null;
        x500principal trustprincipal = null;
        
        // validation date
        {
            errorbundle msg = new errorbundle(resource_name,"certpathreviewer.certpathvaliddate",
                    new object[] {new trustedinput(validdate), new trustedinput(new date())});
            addnotification(msg);
        }
        
        // find trust anchors
        try
        {
            x509certificate cert = (x509certificate) certs.get(certs.size() - 1);
            collection trustcoll = gettrustanchors(cert,pkixparams.gettrustanchors());
            if (trustcoll.size() > 1)
            {
                // conflicting trust anchors                
                errorbundle msg = new errorbundle(resource_name,
                        "certpathreviewer.conflictingtrustanchors",
                        new object[]{integers.valueof(trustcoll.size()),
                            new untrustedinput(cert.getissuerx500principal())});
                adderror(msg);
            }
            else if (trustcoll.isempty())
            {
                errorbundle msg = new errorbundle(resource_name,
                        "certpathreviewer.notrustanchorfound",
                        new object[]{new untrustedinput(cert.getissuerx500principal()),
                            integers.valueof(pkixparams.gettrustanchors().size())});
                adderror(msg);
            }
            else
            {
                publickey trustpublickey;
                trust = (trustanchor) trustcoll.iterator().next();
                if (trust.gettrustedcert() != null)
                {
                    trustpublickey = trust.gettrustedcert().getpublickey();
                }
                else
                {
                    trustpublickey = trust.getcapublickey();
                }
                try
                {
                    certpathvalidatorutilities.verifyx509certificate(cert, trustpublickey,
                        pkixparams.getsigprovider());
                }
                catch (signatureexception e)
                {
                    errorbundle msg = new errorbundle(resource_name,"certpathreviewer.trustbutinvalidcert");
                    adderror(msg);
                }
                catch (exception e)
                {
                    // do nothing, error occurs again later
                }
            }
        }
        catch (certpathreviewerexception cpre)
        {
            adderror(cpre.geterrormessage());
        }
        catch (throwable t)
        {
            errorbundle msg = new errorbundle(resource_name,
                    "certpathreviewer.unknown",
                    new object[] {new untrustedinput(t.getmessage()), new untrustedinput(t)});
            adderror(msg);
        }
        
        if (trust != null)
        {
            // get the name of the trustanchor
            x509certificate sign = trust.gettrustedcert();
            try
            {
                if (sign != null)
                {
                    trustprincipal = getsubjectprincipal(sign);
                }
                else
                {
                    trustprincipal = new x500principal(trust.getcaname());
                }
            }
            catch (illegalargumentexception ex)
            {
                errorbundle msg = new errorbundle(resource_name,"certpathreviewer.trustdninvalid",
                        new object[] {new untrustedinput(trust.getcaname())});
                adderror(msg);
            }
            
            // test key usages of the trust anchor
            if (sign != null)
            {
                boolean[] ku = sign.getkeyusage(); 
                if (ku != null && !ku[5])
                {
                    errorbundle msg = new errorbundle(resource_name, "certpathreviewer.trustkeyusage");
                    addnotification(msg);
                }
            }
        }
        
        // 1.6.2 - initialization
        
        publickey workingpublickey = null;
        x500principal workingissuername = trustprincipal;
        
        x509certificate sign = null;

        algorithmidentifier workingalgid = null;
        derobjectidentifier workingpublickeyalgorithm = null;
        asn1encodable workingpublickeyparameters = null;
        
        if (trust != null)
        {
            sign = trust.gettrustedcert();
            
            if (sign != null)
            {
                workingpublickey = sign.getpublickey();
            }
            else
            {
                workingpublickey = trust.getcapublickey();
            }
        
            try
            {
                workingalgid = getalgorithmidentifier(workingpublickey);
                workingpublickeyalgorithm = workingalgid.getobjectid();
                workingpublickeyparameters = workingalgid.getparameters();
            }
            catch (certpathvalidatorexception ex)
            {
                errorbundle msg = new errorbundle(resource_name,"certpathreviewer.trustpubkeyerror");
                adderror(msg);
                workingalgid = null;
            }
            
        }

        // basic cert checks

        x509certificate cert = null;
        int i;

        for (int index = certs.size() - 1; index >= 0; index--)
        {
            //
            // i as defined in the algorithm description
            //
            i = n - index;

            //
            // set certificate to be checked in this round
            // sign and workingpublickey and workingissuername are set
            // at the end of the for loop and initialied the
            // first time from the trustanchor
            //
            cert = (x509certificate) certs.get(index);

            // verify signature
            if (workingpublickey != null)
            {
                try
                {
                    certpathvalidatorutilities.verifyx509certificate(cert, workingpublickey,
                        pkixparams.getsigprovider());
                }
                catch (generalsecurityexception ex)
                {
                    errorbundle msg = new errorbundle(resource_name,"certpathreviewer.signaturenotverified",
                            new object[] {ex.getmessage(),ex,ex.getclass().getname()}); 
                    adderror(msg,index);
                }
            }
            else if (isselfissued(cert))
            {
                try
                {
                    certpathvalidatorutilities.verifyx509certificate(cert, cert.getpublickey(),
                        pkixparams.getsigprovider());
                    errorbundle msg = new errorbundle(resource_name,"certpathreviewer.rootkeyisvalidbutnotatrustanchor");
                    adderror(msg, index);
                }
                catch (generalsecurityexception ex)
                {
                    errorbundle msg = new errorbundle(resource_name,"certpathreviewer.signaturenotverified",
                            new object[] {ex.getmessage(),ex,ex.getclass().getname()}); 
                    adderror(msg,index);
                }
            }
            else
            {
                errorbundle msg = new errorbundle(resource_name,"certpathreviewer.noissuerpublickey");
                // if there is an authority key extension add the serial and issuer of the missing certificate
                byte[] akibytes = cert.getextensionvalue(x509extensions.authoritykeyidentifier.getid());
                if (akibytes != null)
                {
                    try
                    {
                        authoritykeyidentifier aki = authoritykeyidentifier.getinstance(
                            x509extensionutil.fromextensionvalue(akibytes));
                        generalnames issuernames = aki.getauthoritycertissuer();
                        if (issuernames != null)
                        {
                            generalname name = issuernames.getnames()[0];
                            biginteger serial = aki.getauthoritycertserialnumber(); 
                            if (serial != null)
                            {
                                object[] extraargs = {new localestring(resource_name, "missingissuer"), " \"", name , 
                                        "\" ", new localestring(resource_name, "missingserial") , " ", serial};
                                msg.setextraarguments(extraargs);
                            }
                        }
                    }
                    catch (ioexception e)
                    {
                        // ignore
                    }
                }
                adderror(msg,index);
            }

            // certificate valid?
            try
            {
                cert.checkvalidity(validdate);
            }
            catch (certificatenotyetvalidexception cnve)
            {
                errorbundle msg = new errorbundle(resource_name,"certpathreviewer.certificatenotyetvalid",
                        new object[] {new trustedinput(cert.getnotbefore())});
                adderror(msg,index);
            }
            catch (certificateexpiredexception cee)
            {
                errorbundle msg = new errorbundle(resource_name,"certpathreviewer.certificateexpired",
                        new object[] {new trustedinput(cert.getnotafter())});
                adderror(msg,index);
            }

            // certificate revoked?
            if (pkixparams.isrevocationenabled())
            {
                // read crl distribution points extension
                crldistpoint crldistpoints = null;
                try
                {
                    asn1primitive crl_dp = getextensionvalue(cert,crl_dist_points);
                    if (crl_dp != null)
                    {
                        crldistpoints = crldistpoint.getinstance(crl_dp);
                    }
                }
                catch (annotatedexception ae)
                {
                    errorbundle msg = new errorbundle(resource_name,"certpathreviewer.crldistptexterror");
                    adderror(msg,index);
                }

                // read authority information access extension
                authorityinformationaccess authinfoacc = null;
                try
                {
                    asn1primitive auth_info_acc = getextensionvalue(cert,auth_info_access);
                    if (auth_info_acc != null)
                    {
                        authinfoacc = authorityinformationaccess.getinstance(auth_info_acc);
                    }
                }
                catch (annotatedexception ae)
                {
                    errorbundle msg = new errorbundle(resource_name,"certpathreviewer.crlauthinfoaccerror");
                    adderror(msg,index);
                }
                
                vector crldistpointurls = getcrldisturls(crldistpoints);
                vector ocspurls = getocspurls(authinfoacc);
                
                // add notifications with the crl distribution points
                
                // output crl distribution points
                iterator urlit = crldistpointurls.iterator();
                while (urlit.hasnext())
                {
                    errorbundle msg = new errorbundle(resource_name,"certpathreviewer.crldistpoint",
                                new object[] {new untrustedurlinput(urlit.next())});
                    addnotification(msg,index);
                }
                
                // output ocsp urls
                urlit = ocspurls.iterator();
                while (urlit.hasnext())
                {
                    errorbundle msg = new errorbundle(resource_name,"certpathreviewer.ocsplocation",
                            new object[] {new untrustedurlinput(urlit.next())});
                    addnotification(msg,index);
                }
                
                // todo also support netscapes revocation-url and/or ocsp instead of crls for revocation checking
                // check crls
                try 
                {
                    checkrevocation(pkixparams, cert, validdate, sign, workingpublickey, crldistpointurls, ocspurls, index);
                }
                catch (certpathreviewerexception cpre)
                {
                    adderror(cpre.geterrormessage(),index);
                }
            }

            // certificate issuer correct
            if (workingissuername != null && !cert.getissuerx500principal().equals(workingissuername))
            {
                errorbundle msg = new errorbundle(resource_name,"certpathreviewer.certwrongissuer",
                            new object[] {workingissuername.getname(),
                            cert.getissuerx500principal().getname()});
                adderror(msg,index);
            }

            //
            // prepare for next certificate
            //
            if (i != n)
            {

                if (cert != null && cert.getversion() == 1)
                {
                    errorbundle msg = new errorbundle(resource_name,"certpathreviewer.nocacert");
                    adderror(msg,index);
                }

                // k)

                basicconstraints bc;
                try
                {
                    bc = basicconstraints.getinstance(getextensionvalue(cert,
                            basic_constraints));
                    if (bc != null)
                    {
                        if (!bc.isca())
                        {
                            errorbundle msg = new errorbundle(resource_name,"certpathreviewer.nocacert");
                            adderror(msg,index);
                        }
                    }
                    else
                    {
                        errorbundle msg = new errorbundle(resource_name,"certpathreviewer.nobasicconstraints");
                        adderror(msg,index);
                    }
                }
                catch (annotatedexception ae)
                {
                    errorbundle msg = new errorbundle(resource_name,"certpathreviewer.errorprocesingbc");
                    adderror(msg,index);
                }

                // n)

                boolean[] _usage = cert.getkeyusage();

                if ((_usage != null) && !_usage[key_cert_sign])
                {
                    errorbundle msg = new errorbundle(resource_name,"certpathreviewer.nocertsign");
                    adderror(msg,index);
                }

            } // if

            // set signing certificate for next round
            sign = cert;
            
            // c)

            workingissuername = cert.getsubjectx500principal();

            // d) e) f)

            try
            {
                workingpublickey = getnextworkingkey(certs, index);
                workingalgid = getalgorithmidentifier(workingpublickey);
                workingpublickeyalgorithm = workingalgid.getobjectid();
                workingpublickeyparameters = workingalgid.getparameters();
            }
            catch (certpathvalidatorexception ex)
            {
                errorbundle msg = new errorbundle(resource_name,"certpathreviewer.pubkeyerror");
                adderror(msg,index);
                workingalgid = null;
                workingpublickeyalgorithm = null;
                workingpublickeyparameters = null;
            }

        } // for

        trustanchor = trust;
        subjectpublickey = workingpublickey;
    }

    private void checkpolicy()
    {
        //
        // 6.1.1 inputs
        //

        // c) initial policy set

        set userinitialpolicyset = pkixparams.getinitialpolicies();

        // e) f) g) are part of pkixparams

        //
        // 6.1.2 initialization
        //

        // a) valid policy tree

        list[] policynodes = new arraylist[n + 1];
        for (int j = 0; j < policynodes.length; j++)
        {
            policynodes[j] = new arraylist();
        }

        set policyset = new hashset();

        policyset.add(any_policy);

        pkixpolicynode validpolicytree = new pkixpolicynode(new arraylist(), 0,
                policyset, null, new hashset(), any_policy, false);

        policynodes[0].add(validpolicytree);

        // d) explicit policy

        int explicitpolicy;
        if (pkixparams.isexplicitpolicyrequired())
        {
            explicitpolicy = 0;
        }
        else
        {
            explicitpolicy = n + 1;
        }

        // e) inhibit any policy

        int inhibitanypolicy;
        if (pkixparams.isanypolicyinhibited())
        {
            inhibitanypolicy = 0;
        }
        else
        {
            inhibitanypolicy = n + 1;
        }

        // f) policy mapping

        int policymapping;
        if (pkixparams.ispolicymappinginhibited())
        {
            policymapping = 0;
        }
        else
        {
            policymapping = n + 1;
        }

        set acceptablepolicies = null;

        //
        // 6.1.3 basic certificate processing
        //

        x509certificate cert = null;
        int index;
        int i;

        try 
        {
            for (index = certs.size() - 1; index >= 0; index--)
            {
                // i as defined in the algorithm description
                i = n - index;
    
                // set certificate to be checked in this round
                cert = (x509certificate) certs.get(index);
    
                // d) process policy information
    
                asn1sequence certpolicies;
                try 
                {
                    certpolicies = (asn1sequence) getextensionvalue(
                        cert, certificate_policies);
                }
                catch (annotatedexception ae)
                {
                    errorbundle msg = new errorbundle(resource_name,"certpathreviewer.policyexterror");
                    throw new certpathreviewerexception(msg,ae,certpath,index);
                }
                if (certpolicies != null && validpolicytree != null)
                {

                    // d) 1)

                    enumeration e = certpolicies.getobjects();
                    set pols = new hashset();

                    while (e.hasmoreelements())
                    {
                        policyinformation pinfo = policyinformation.getinstance(e.nextelement());
                        derobjectidentifier poid = pinfo.getpolicyidentifier();

                        pols.add(poid.getid());

                        if (!any_policy.equals(poid.getid()))
                        {
                            set pq;
                            try
                            {
                                pq = getqualifierset(pinfo.getpolicyqualifiers());
                            }
                            catch (certpathvalidatorexception cpve)
                            {
                                errorbundle msg = new errorbundle(resource_name,"certpathreviewer.policyqualifiererror");
                                throw new certpathreviewerexception(msg,cpve,certpath,index);
                            }

                            boolean match = processcertd1i(i, policynodes, poid, pq);

                            if (!match)
                            {
                                processcertd1ii(i, policynodes, poid, pq);
                            }
                        }
                    }

                    if (acceptablepolicies == null || acceptablepolicies.contains(any_policy))
                    {
                        acceptablepolicies = pols;
                    }
                    else
                    {
                        iterator it = acceptablepolicies.iterator();
                        set t1 = new hashset();

                        while (it.hasnext())
                        {
                            object o = it.next();

                            if (pols.contains(o))
                            {
                                t1.add(o);
                            }
                        }

                        acceptablepolicies = t1;
                    }

                    // d) 2)

                    if ((inhibitanypolicy > 0) || ((i < n) && isselfissued(cert)))
                    {
                        e = certpolicies.getobjects();

                        while (e.hasmoreelements())
                        {
                            policyinformation pinfo = policyinformation.getinstance(e.nextelement());

                            if (any_policy.equals(pinfo.getpolicyidentifier().getid()))
                            {
                                set _apq;
                                try
                                {
                                    _apq = getqualifierset(pinfo.getpolicyqualifiers());
                                }
                                catch (certpathvalidatorexception cpve)
                                {
                                    errorbundle msg = new errorbundle(resource_name,"certpathreviewer.policyqualifiererror");
                                    throw new certpathreviewerexception(msg,cpve,certpath,index);
                                }
                                list _nodes = policynodes[i - 1];

                                for (int k = 0; k < _nodes.size(); k++)
                                {
                                    pkixpolicynode _node = (pkixpolicynode) _nodes.get(k);

                                    iterator _policysetiter = _node.getexpectedpolicies().iterator();
                                    while (_policysetiter.hasnext())
                                    {
                                        object _tmp = _policysetiter.next();

                                        string _policy;
                                        if (_tmp instanceof string)
                                        {
                                            _policy = (string) _tmp;
                                        }
                                        else if (_tmp instanceof derobjectidentifier)
                                        {
                                            _policy = ((derobjectidentifier) _tmp).getid();
                                        }
                                        else
                                        {
                                            continue;
                                        }

                                        boolean _found = false;
                                        iterator _childreniter = _node
                                                .getchildren();

                                        while (_childreniter.hasnext())
                                        {
                                            pkixpolicynode _child = (pkixpolicynode) _childreniter.next();

                                            if (_policy.equals(_child.getvalidpolicy()))
                                            {
                                                _found = true;
                                            }
                                        }

                                        if (!_found)
                                        {
                                            set _newchildexpectedpolicies = new hashset();
                                            _newchildexpectedpolicies.add(_policy);

                                            pkixpolicynode _newchild = new pkixpolicynode(
                                                    new arraylist(), i,
                                                    _newchildexpectedpolicies,
                                                    _node, _apq, _policy, false);
                                            _node.addchild(_newchild);
                                            policynodes[i].add(_newchild);
                                        }
                                    }
                                }
                                break;
                            }
                        }
                    }

                    //
                    // (d) (3)
                    //
                    for (int j = (i - 1); j >= 0; j--)
                    {
                        list nodes = policynodes[j];

                        for (int k = 0; k < nodes.size(); k++)
                        {
                            pkixpolicynode node = (pkixpolicynode) nodes.get(k);
                            if (!node.haschildren())
                            {
                                validpolicytree = removepolicynode(
                                        validpolicytree, policynodes, node);
                                if (validpolicytree == null)
                                {
                                    break;
                                }
                            }
                        }
                    }

                    //
                    // d (4)
                    //
                    set criticalextensionoids = cert.getcriticalextensionoids();

                    if (criticalextensionoids != null)
                    {
                        boolean critical = criticalextensionoids.contains(certificate_policies);

                        list nodes = policynodes[i];
                        for (int j = 0; j < nodes.size(); j++)
                        {
                            pkixpolicynode node = (pkixpolicynode) nodes.get(j);
                            node.setcritical(critical);
                        }
                    }

                }
                
                // e)
                
                if (certpolicies == null) 
                {
                    validpolicytree = null;
                }
                
                // f)
                
                if (explicitpolicy <= 0 && validpolicytree == null)
                {
                    errorbundle msg = new errorbundle(resource_name,"certpathreviewer.novalidpolicytree");
                    throw new certpathreviewerexception(msg);
                }
    
                //
                // 6.1.4 preparation for next certificate
                //
    
                if (i != n)
                {
                    
                    // a)
                    
                    asn1primitive pm;
                    try
                    {
                        pm = getextensionvalue(cert, policy_mappings);
                    }
                    catch (annotatedexception ae)
                    {
                        errorbundle msg = new errorbundle(resource_name,"certpathreviewer.policymapexterror");
                        throw new certpathreviewerexception(msg,ae,certpath,index);
                    }
                    
                    if (pm != null) 
                    {
                        asn1sequence mappings = (asn1sequence) pm;
                        for (int j = 0; j < mappings.size(); j++) 
                        {
                            asn1sequence mapping = (asn1sequence) mappings.getobjectat(j);
                            derobjectidentifier ip_id = (derobjectidentifier) mapping.getobjectat(0);
                            derobjectidentifier sp_id = (derobjectidentifier) mapping.getobjectat(1);
                            if (any_policy.equals(ip_id.getid())) 
                            {
                                errorbundle msg = new errorbundle(resource_name,"certpathreviewer.invalidpolicymapping");
                                throw new certpathreviewerexception(msg,certpath,index);
                            }
                            if (any_policy.equals(sp_id.getid()))
                            {
                                errorbundle msg = new errorbundle(resource_name,"certpathreviewer.invalidpolicymapping");
                                throw new certpathreviewerexception(msg,certpath,index);
                            }
                        }
                    }
                    
                    // b)
                    
                    if (pm != null)
                    {
                        asn1sequence mappings = (asn1sequence)pm;
                        map m_idp = new hashmap();
                        set s_idp = new hashset();
                        
                        for (int j = 0; j < mappings.size(); j++)
                        {
                            asn1sequence mapping = (asn1sequence)mappings.getobjectat(j);
                            string id_p = ((derobjectidentifier)mapping.getobjectat(0)).getid();
                            string sd_p = ((derobjectidentifier)mapping.getobjectat(1)).getid();
                            set tmp;
                            
                            if (!m_idp.containskey(id_p))
                            {
                                tmp = new hashset();
                                tmp.add(sd_p);
                                m_idp.put(id_p, tmp);
                                s_idp.add(id_p);
                            }
                            else
                            {
                                tmp = (set)m_idp.get(id_p);
                                tmp.add(sd_p);
                            }
                        }
    
                        iterator it_idp = s_idp.iterator();
                        while (it_idp.hasnext())
                        {
                            string id_p = (string)it_idp.next();
                            
                            //
                            // (1)
                            //
                            if (policymapping > 0)
                            {
                                try
                                {
                                    preparenextcertb1(i,policynodes,id_p,m_idp,cert);
                                }
                                catch (annotatedexception ae)
                                {
                                    // error processing certificate policies extension
                                    errorbundle msg = new errorbundle(resource_name,"certpathreviewer.policyexterror");
                                    throw new certpathreviewerexception(msg,ae,certpath,index);
                                }
                                catch (certpathvalidatorexception cpve)
                                {
                                    // error building qualifier set
                                    errorbundle msg = new errorbundle(resource_name,"certpathreviewer.policyqualifiererror");
                                    throw new certpathreviewerexception(msg,cpve,certpath,index);
                                }
                                
                                //
                                // (2)
                                // 
                            }
                            else if (policymapping <= 0)
                            {
                                validpolicytree = preparenextcertb2(i,policynodes,id_p,validpolicytree);
                            }
                            
                        }
                    }
                    
                    //
                    // h)
                    //
                    
                    if (!isselfissued(cert)) 
                    {
                        
                        // (1)
                        if (explicitpolicy != 0)
                        {
                            explicitpolicy--;
                        }
                        
                        // (2)
                        if (policymapping != 0)
                        {
                            policymapping--;
                        }
                        
                        // (3)
                        if (inhibitanypolicy != 0)
                        {
                            inhibitanypolicy--;
                        }
                        
                    }
    
                    //
                    // i)
                    //
                    
                    try
                    {
                        asn1sequence pc = (asn1sequence) getextensionvalue(cert,policy_constraints);
                        if (pc != null)
                        {
                            enumeration policyconstraints = pc.getobjects();
                            
                            while (policyconstraints.hasmoreelements())
                            {
                                asn1taggedobject constraint = (asn1taggedobject) policyconstraints.nextelement();
                                int tmpint; 
                                
                                switch (constraint.gettagno())
                                {
                                case 0:
                                    tmpint = derinteger.getinstance(constraint, false).getvalue().intvalue();
                                    if (tmpint < explicitpolicy)
                                    {
                                        explicitpolicy = tmpint;
                                    }
                                    break;
                                case 1:
                                    tmpint = derinteger.getinstance(constraint, false).getvalue().intvalue();
                                    if (tmpint < policymapping)
                                    {
                                        policymapping = tmpint;
                                    }
                                break;
                                }
                            }
                        }
                    }
                    catch (annotatedexception ae)
                    {
                        errorbundle msg = new errorbundle(resource_name,"certpathreviewer.policyconstexterror");
                        throw new certpathreviewerexception(msg,certpath,index);
                    }
    
                    //
                    // j)
                    //
                    
                    try 
                    {
                        derinteger iap = (derinteger)getextensionvalue(cert, inhibit_any_policy);
                        
                        if (iap != null)
                        {
                            int _inhibitanypolicy = iap.getvalue().intvalue();
                        
                            if (_inhibitanypolicy < inhibitanypolicy)
                            {
                                inhibitanypolicy = _inhibitanypolicy;
                            }
                        }
                    }
                    catch (annotatedexception ae)
                    {
                        errorbundle msg = new errorbundle(resource_name,"certpathreviewer.policyinhibitexterror");
                        throw new certpathreviewerexception(msg,certpath,index);
                    }
                }
    
            }
    
            //
            // 6.1.5 wrap up
            //
    
            //
            // a)
            //
            
            if (!isselfissued(cert) && explicitpolicy > 0) 
            {
                explicitpolicy--;
            }
    
            //
            // b)
            //
            
            try
            {
                asn1sequence pc = (asn1sequence) getextensionvalue(cert, policy_constraints);
                if (pc != null)
                {
                    enumeration policyconstraints = pc.getobjects();
        
                    while (policyconstraints.hasmoreelements())
                    {
                        asn1taggedobject    constraint = (asn1taggedobject)policyconstraints.nextelement();
                        switch (constraint.gettagno())
                        {
                        case 0:
                            int tmpint = derinteger.getinstance(constraint, false).getvalue().intvalue();
                            if (tmpint == 0)
                            {
                                explicitpolicy = 0;
                            }
                            break;
                        }
                    }
                }
            }
            catch (annotatedexception e)
            {
                errorbundle msg = new errorbundle(resource_name,"certpathreviewer.policyconstexterror");
                throw new certpathreviewerexception(msg,certpath,index);
            }
            
            
            //
            // (g)
            //
            pkixpolicynode intersection;
            
    
            //
            // (g) (i)
            //
            if (validpolicytree == null)
            { 
                if (pkixparams.isexplicitpolicyrequired())
                {
                    errorbundle msg = new errorbundle(resource_name,"certpathreviewer.explicitpolicy");
                    throw new certpathreviewerexception(msg,certpath,index);
                }
                intersection = null;
            }
            else if (isanypolicy(userinitialpolicyset)) // (g) (ii)
            {
                if (pkixparams.isexplicitpolicyrequired())
                {
                    if (acceptablepolicies.isempty())
                    {
                        errorbundle msg = new errorbundle(resource_name,"certpathreviewer.explicitpolicy");
                        throw new certpathreviewerexception(msg,certpath,index);
                    }
                    else
                    {
                        set _validpolicynodeset = new hashset();
                        
                        for (int j = 0; j < policynodes.length; j++)
                        {
                            list      _nodedepth = policynodes[j];
                            
                            for (int k = 0; k < _nodedepth.size(); k++)
                            {
                                pkixpolicynode _node = (pkixpolicynode)_nodedepth.get(k);
                                
                                if (any_policy.equals(_node.getvalidpolicy()))
                                {
                                    iterator _iter = _node.getchildren();
                                    while (_iter.hasnext())
                                    {
                                        _validpolicynodeset.add(_iter.next());
                                    }
                                }
                            }
                        }
                        
                        iterator _vpnsiter = _validpolicynodeset.iterator();
                        while (_vpnsiter.hasnext())
                        {
                            pkixpolicynode _node = (pkixpolicynode)_vpnsiter.next();
                            string _validpolicy = _node.getvalidpolicy();
                            
                            if (!acceptablepolicies.contains(_validpolicy))
                            {
                                //validpolicytree = removepolicynode(validpolicytree, policynodes, _node);
                            }
                        }
                        if (validpolicytree != null)
                        {
                            for (int j = (n - 1); j >= 0; j--)
                            {
                                list      nodes = policynodes[j];
                                
                                for (int k = 0; k < nodes.size(); k++)
                                {
                                    pkixpolicynode node = (pkixpolicynode)nodes.get(k);
                                    if (!node.haschildren())
                                    {
                                        validpolicytree = removepolicynode(validpolicytree, policynodes, node);
                                    }
                                }
                            }
                        }
                    }
                }
    
                intersection = validpolicytree;
            }
            else
            {
                //
                // (g) (iii)
                //
                // this implementation is not exactly same as the one described in rfc3280.
                // however, as far as the validation result is concerned, both produce 
                // adequate result. the only difference is whether anypolicy is remain 
                // in the policy tree or not. 
                //
                // (g) (iii) 1
                //
                set _validpolicynodeset = new hashset();
                
                for (int j = 0; j < policynodes.length; j++)
                {
                    list      _nodedepth = policynodes[j];
                    
                    for (int k = 0; k < _nodedepth.size(); k++)
                    {
                        pkixpolicynode _node = (pkixpolicynode)_nodedepth.get(k);
                        
                        if (any_policy.equals(_node.getvalidpolicy()))
                        {
                            iterator _iter = _node.getchildren();
                            while (_iter.hasnext())
                            {
                                pkixpolicynode _c_node = (pkixpolicynode)_iter.next();
                                if (!any_policy.equals(_c_node.getvalidpolicy()))
                                {
                                    _validpolicynodeset.add(_c_node);
                                }
                            }
                        }
                    }
                }
                
                //
                // (g) (iii) 2
                //
                iterator _vpnsiter = _validpolicynodeset.iterator();
                while (_vpnsiter.hasnext())
                {
                    pkixpolicynode _node = (pkixpolicynode)_vpnsiter.next();
                    string _validpolicy = _node.getvalidpolicy();
    
                    if (!userinitialpolicyset.contains(_validpolicy))
                    {
                        validpolicytree = removepolicynode(validpolicytree, policynodes, _node);
                    }
                }
                
                //
                // (g) (iii) 4
                //
                if (validpolicytree != null)
                {
                    for (int j = (n - 1); j >= 0; j--)
                    {
                        list      nodes = policynodes[j];
                        
                        for (int k = 0; k < nodes.size(); k++)
                        {
                            pkixpolicynode node = (pkixpolicynode)nodes.get(k);
                            if (!node.haschildren())
                            {
                                validpolicytree = removepolicynode(validpolicytree, policynodes, node);
                            }
                        }
                    }
                }
                
                intersection = validpolicytree;
            }
     
            if ((explicitpolicy <= 0) && (intersection == null))
            {
                errorbundle msg = new errorbundle(resource_name,"certpathreviewer.invalidpolicy");
                throw new certpathreviewerexception(msg);
            }
            
            validpolicytree = intersection;
        }
        catch (certpathreviewerexception cpre)
        {
            adderror(cpre.geterrormessage(),cpre.getindex());
            validpolicytree = null;
        }
    }

    private void checkcriticalextensions()
    {
        //      
        // initialise certpathchecker's
        //
        list  pathcheckers = pkixparams.getcertpathcheckers();
        iterator certiter = pathcheckers.iterator();
        
        try
        {
            try
            {
                while (certiter.hasnext())
                {
                    ((pkixcertpathchecker)certiter.next()).init(false);
                }
            }
            catch (certpathvalidatorexception cpve)
            {
                errorbundle msg = new errorbundle(resource_name,"certpathreviewer.certpathcheckererror",
                        new object[] {cpve.getmessage(),cpve,cpve.getclass().getname()});
                throw new certpathreviewerexception(msg,cpve);
            }
            
            //
            // process critical extesions for each certificate
            //
            
            x509certificate cert = null;
            
            int index;
            
            for (index = certs.size()-1; index >= 0; index--)
            {
                cert = (x509certificate) certs.get(index);
                
                set criticalextensions = cert.getcriticalextensionoids();
                if (criticalextensions == null || criticalextensions.isempty())
                {
                    continue;
                }
                // remove already processed extensions
                criticalextensions.remove(key_usage);
                criticalextensions.remove(certificate_policies);
                criticalextensions.remove(policy_mappings);
                criticalextensions.remove(inhibit_any_policy);
                criticalextensions.remove(issuing_distribution_point);
                criticalextensions.remove(delta_crl_indicator);
                criticalextensions.remove(policy_constraints);
                criticalextensions.remove(basic_constraints);
                criticalextensions.remove(subject_alternative_name);
                criticalextensions.remove(name_constraints);
                
                // process qcstatements extension
                if (criticalextensions.contains(qc_statement))
                {
                    if (processqcstatements(cert,index)) 
                    {
                        criticalextensions.remove(qc_statement);
                    }
                }
                
                iterator tmpiter = pathcheckers.iterator();
                while (tmpiter.hasnext())
                {
                    try
                    {
                        ((pkixcertpathchecker)tmpiter.next()).check(cert, criticalextensions);
                    }
                    catch (certpathvalidatorexception e)
                    {
                        errorbundle msg = new errorbundle(resource_name,"certpathreviewer.criticalextensionerror",
                                new object[] {e.getmessage(),e,e.getclass().getname()});
                        throw new certpathreviewerexception(msg,e.getcause(),certpath,index);
                    }
                }
                if (!criticalextensions.isempty())
                {
                    errorbundle msg;
                    iterator it = criticalextensions.iterator();
                    while (it.hasnext())
                    {
                        msg = new errorbundle(resource_name,"certpathreviewer.unknowncriticalext",
                                new object[] {new derobjectidentifier((string) it.next())});
                        adderror(msg, index);
                    }
                }
            }
        }
        catch (certpathreviewerexception cpre)
        {
            adderror(cpre.geterrormessage(),cpre.getindex());
        }
    }
    
    private boolean processqcstatements(
            x509certificate cert,
            int index)
    {   
        try
        {
            boolean unknownstatement = false;
            
            asn1sequence qcst = (asn1sequence) getextensionvalue(cert,qc_statement);
            for (int j = 0; j < qcst.size(); j++)
            {
                qcstatement stmt = qcstatement.getinstance(qcst.getobjectat(j));
                if (qcstatement.id_etsi_qcs_qccompliance.equals(stmt.getstatementid()))
                {
                    // process statement - just write a notification that the certificate contains this statement
                    errorbundle msg = new errorbundle(resource_name,"certpathreviewer.qceucompliance");
                    addnotification(msg,index);
                }
                else if (qcstatement.id_qcs_pkixqcsyntax_v1.equals(stmt.getstatementid()))
                {
                    // process statement - just recognize the statement
                }
                else if (qcstatement.id_etsi_qcs_qcsscd.equals(stmt.getstatementid()))
                {
                    // process statement - just write a notification that the certificate contains this statement
                    errorbundle msg = new errorbundle(resource_name,"certpathreviewer.qcsscd");
                    addnotification(msg,index);
                }
                else if (qcstatement.id_etsi_qcs_limitevalue.equals(stmt.getstatementid()))
                {
                    // process statement - write a notification containing the limit value
                    monetaryvalue limit = monetaryvalue.getinstance(stmt.getstatementinfo());
                    iso4217currencycode currency = limit.getcurrency();
                    double value = limit.getamount().doublevalue() * math.pow(10,limit.getexponent().doublevalue());
                    errorbundle msg;
                    if (limit.getcurrency().isalphabetic())
                    {
                        msg = new errorbundle(resource_name,"certpathreviewer.qclimitvaluealpha",
                                new object[] {limit.getcurrency().getalphabetic(),
                                              new trustedinput(new double(value)),
                                              limit});
                    }
                    else
                    {
                        msg = new errorbundle(resource_name,"certpathreviewer.qclimitvaluenum",
                                new object[]{integers.valueof(limit.getcurrency().getnumeric()),
                                    new trustedinput(new double(value)),
                                    limit});
                    }
                    addnotification(msg,index);
                }
                else
                {
                    errorbundle msg = new errorbundle(resource_name,"certpathreviewer.qcunknownstatement",
                            new object[] {stmt.getstatementid(),new untrustedinput(stmt)});
                    addnotification(msg,index);
                    unknownstatement = true;
                }
            }
            
            return !unknownstatement;
        }
        catch (annotatedexception ae)
        {
            errorbundle msg = new errorbundle(resource_name,"certpathreviewer.qcstatementexterror");
            adderror(msg,index);
        }
        
        return false;
    }
    
    private string iptostring(byte[] ip)
    {
        string result;
        try
        {
            result = inetaddress.getbyaddress(ip).gethostaddress();
        }
        catch (exception e)
        {
            stringbuffer b = new stringbuffer();
            
            for (int i = 0; i != ip.length; i++)
            {
                b.append(integer.tohexstring(ip[i] & 0xff));
                b.append(' ');
            }
            
            result = b.tostring();
        }
        
        return result;
    }
    
    protected void checkrevocation(pkixparameters paramspkix,
            x509certificate cert,
            date validdate,
            x509certificate sign,
            publickey workingpublickey,
            vector crldistpointurls,
            vector ocspurls,
            int index)
        throws certpathreviewerexception
    {
        checkcrls(paramspkix, cert, validdate, sign, workingpublickey, crldistpointurls, index);
    }
    
    protected void checkcrls(
            pkixparameters paramspkix,
            x509certificate cert,
            date validdate,
            x509certificate sign,
            publickey workingpublickey,
            vector crldistpointurls,
            int index) 
        throws certpathreviewerexception
    {
        x509crlstoreselector crlselect;
        crlselect = new x509crlstoreselector();
        
        try
        {
            crlselect.addissuername(getencodedissuerprincipal(cert).getencoded());
        }
        catch (ioexception e)
        {
            errorbundle msg = new errorbundle(resource_name,"certpathreviewer.crlissuerexception");
            throw new certpathreviewerexception(msg,e);
        }
    
        crlselect.setcertificatechecking(cert);
    
        iterator crl_iter;
        try 
        {
            collection crl_coll = crl_util.findcrls(crlselect, paramspkix);
            crl_iter = crl_coll.iterator();
            
            if (crl_coll.isempty())
            {
                // notifcation - no local crls found
                crl_coll = crl_util.findcrls(new x509crlstoreselector(),paramspkix);
                iterator it = crl_coll.iterator();
                list nonmatchingcrlnames = new arraylist();
                while (it.hasnext())
                {
                    nonmatchingcrlnames.add(((x509crl) it.next()).getissuerx500principal());
                }
                int numbofcrls = nonmatchingcrlnames.size();
                errorbundle msg = new errorbundle(resource_name,
                        "certpathreviewer.nocrlincertstore",
                        new object[]{new untrustedinput(crlselect.getissuernames()),
                            new untrustedinput(nonmatchingcrlnames),
                            integers.valueof(numbofcrls)});
                addnotification(msg,index);
            }

        }
        catch (annotatedexception ae)
        {
            errorbundle msg = new errorbundle(resource_name,"certpathreviewer.crlextractionerror",
                    new object[] {ae.getcause().getmessage(),ae.getcause(),ae.getcause().getclass().getname()});
            adderror(msg,index);
            crl_iter = new arraylist().iterator();
        }
        boolean validcrlfound = false;
        x509crl crl = null;
        while (crl_iter.hasnext())
        {
            crl = (x509crl)crl_iter.next();
            
            if (crl.getnextupdate() == null
                || paramspkix.getdate().before(crl.getnextupdate()))
            {
                validcrlfound = true;
                errorbundle msg = new errorbundle(resource_name,
                        "certpathreviewer.localvalidcrl",
                        new object[] {new trustedinput(crl.getthisupdate()), new trustedinput(crl.getnextupdate())});
                addnotification(msg,index);
                break;
            }
            else
            {
                errorbundle msg = new errorbundle(resource_name,
                        "certpathreviewer.localinvalidcrl",
                        new object[] {new trustedinput(crl.getthisupdate()), new trustedinput(crl.getnextupdate())});
                addnotification(msg,index);
            }
        }
        
        // if no valid crl was found in the certstores try to get one from a
        // crl distribution point
        if (!validcrlfound)
        {
            x509crl onlinecrl = null;
            iterator urlit = crldistpointurls.iterator();
            while (urlit.hasnext())
            {
                try
                {
                    string location = (string) urlit.next();
                    onlinecrl = getcrl(location);
                    if (onlinecrl != null)
                    {
                        // check if crl issuer is correct
                        if (!cert.getissuerx500principal().equals(onlinecrl.getissuerx500principal()))
                        {
                            errorbundle msg = new errorbundle(resource_name,
                                        "certpathreviewer.onlinecrlwrongca",
                                        new object[] {new untrustedinput(onlinecrl.getissuerx500principal().getname()),
                                                      new untrustedinput(cert.getissuerx500principal().getname()),
                                                      new untrustedurlinput(location)});
                            addnotification(msg,index);
                            continue;
                        }
                        
                        if (onlinecrl.getnextupdate() == null
                            || pkixparams.getdate().before(onlinecrl.getnextupdate()))
                        {
                            validcrlfound = true;
                            errorbundle msg = new errorbundle(resource_name,
                                    "certpathreviewer.onlinevalidcrl",
                                    new object[] {new trustedinput(onlinecrl.getthisupdate()),
                                                  new trustedinput(onlinecrl.getnextupdate()),
                                                  new untrustedurlinput(location)});
                            addnotification(msg,index);
                            crl = onlinecrl;
                            break;
                        }
                        else
                        {
                            errorbundle msg = new errorbundle(resource_name,
                                    "certpathreviewer.onlineinvalidcrl",
                                    new object[] {new trustedinput(onlinecrl.getthisupdate()),
                                                  new trustedinput(onlinecrl.getnextupdate()),
                                                  new untrustedurlinput(location)});
                            addnotification(msg,index);
                        }
                    }
                }
                catch (certpathreviewerexception cpre)
                {
                    addnotification(cpre.geterrormessage(),index);
                }
            }
        }
        
        // check the crl
        x509crlentry crl_entry;
        if (crl != null)
        {
            if (sign != null)
            {
                boolean[] keyusage = sign.getkeyusage();

                if (keyusage != null
                    && (keyusage.length < 7 || !keyusage[crl_sign]))
                {
                    errorbundle msg = new errorbundle(resource_name,"certpathreviewer.nocrlsigningpermited");
                    throw new certpathreviewerexception(msg);
                }
            }

            if (workingpublickey != null)
            {
                try
                {
                    crl.verify(workingpublickey, "bc");
                }
                catch (exception e)
                {
                    errorbundle msg = new errorbundle(resource_name,"certpathreviewer.crlverifyfailed");
                    throw new certpathreviewerexception(msg,e);
                }
            }
            else // issuer public key not known
            {
                errorbundle msg = new errorbundle(resource_name,"certpathreviewer.crlnoissuerpublickey");
                throw new certpathreviewerexception(msg);
            }

            crl_entry = crl.getrevokedcertificate(cert.getserialnumber());
            if (crl_entry != null)
            {
                string reason = null;
                
                if (crl_entry.hasextensions())
                {
                    derenumerated reasoncode;
                    try
                    {
                        reasoncode = derenumerated.getinstance(getextensionvalue(crl_entry, x509extensions.reasoncode.getid()));
                    }
                    catch (annotatedexception ae)
                    {
                        errorbundle msg = new errorbundle(resource_name,"certpathreviewer.crlreasonexterror");
                        throw new certpathreviewerexception(msg,ae);
                    }
                    if (reasoncode != null)
                    {
                        reason = crlreasons[reasoncode.getvalue().intvalue()];
                    }
                }

                if (reason == null)
                {
                    reason = crlreasons[7]; // unknown
                }

                // i18n reason
                localestring ls = new localestring(resource_name, reason);
                
                if (!validdate.before(crl_entry.getrevocationdate()))
                {
                    errorbundle msg = new errorbundle(resource_name,"certpathreviewer.certrevoked",
                            new object[] {new trustedinput(crl_entry.getrevocationdate()),ls});
                    throw new certpathreviewerexception(msg);
                }
                else // cert was revoked after validation date
                {
                    errorbundle msg = new errorbundle(resource_name,"certpathreviewer.revokedaftervalidation",
                            new object[] {new trustedinput(crl_entry.getrevocationdate()),ls});
                    addnotification(msg,index);
                }
            }
            else // cert is not revoked
            {
                errorbundle msg = new errorbundle(resource_name,"certpathreviewer.notrevoked");
                addnotification(msg,index);
            }
            
            //
            // warn if a new crl is available
            //
            if (crl.getnextupdate() != null && crl.getnextupdate().before(pkixparams.getdate()))
            {
                errorbundle msg = new errorbundle(resource_name,"certpathreviewer.crlupdateavailable",
                        new object[] {new trustedinput(crl.getnextupdate())});
                addnotification(msg,index);
            }
            
            //
            // check the deltacrl indicator, base point and the issuing distribution point
            //
            asn1primitive idp;
            try
            {
                idp = getextensionvalue(crl, issuing_distribution_point);
            }
            catch (annotatedexception ae)
            {
                errorbundle msg = new errorbundle(resource_name,"certpathreviewer.distrptexterror");
                throw new certpathreviewerexception(msg);
            }
            asn1primitive dci;
            try
            {
                dci = getextensionvalue(crl, delta_crl_indicator);
            }
            catch (annotatedexception ae)
            {
                errorbundle msg = new errorbundle(resource_name,"certpathreviewer.deltacrlexterror");
                throw new certpathreviewerexception(msg);
            }

            if (dci != null)
            {
                x509crlstoreselector baseselect = new x509crlstoreselector();

                try
                {
                    baseselect.addissuername(getissuerprincipal(crl).getencoded());
                }
                catch (ioexception e)
                {
                    errorbundle msg = new errorbundle(resource_name,"certpathreviewer.crlissuerexception");
                    throw new certpathreviewerexception(msg,e);
                }

                baseselect.setmincrlnumber(((derinteger)dci).getpositivevalue());
                try
                {
                    baseselect.setmaxcrlnumber(((derinteger)getextensionvalue(crl, crl_number)).getpositivevalue().subtract(biginteger.valueof(1)));
                }
                catch (annotatedexception ae)
                {
                    errorbundle msg = new errorbundle(resource_name,"certpathreviewer.crlnbrexterror");
                    throw new certpathreviewerexception(msg,ae);
                }
                
                boolean  foundbase = false;
                iterator it;
                try 
                {
                    it  = crl_util.findcrls(baseselect, paramspkix).iterator();
                }
                catch (annotatedexception ae)
                {
                    errorbundle msg = new errorbundle(resource_name,"certpathreviewer.crlextractionerror");
                    throw new certpathreviewerexception(msg,ae);
                }
                while (it.hasnext())
                {
                    x509crl base = (x509crl)it.next();

                    asn1primitive baseidp;
                    try
                    {
                        baseidp = getextensionvalue(base, issuing_distribution_point);
                    }
                    catch (annotatedexception ae)
                    {
                        errorbundle msg = new errorbundle(resource_name,"certpathreviewer.distrptexterror");
                        throw new certpathreviewerexception(msg,ae);
                    }
                    
                    if (idp == null)
                    {
                        if (baseidp == null)
                        {
                            foundbase = true;
                            break;
                        }
                    }
                    else
                    {
                        if (idp.equals(baseidp))
                        {
                            foundbase = true;
                            break;
                        }
                    }
                }
                
                if (!foundbase)
                {
                    errorbundle msg = new errorbundle(resource_name,"certpathreviewer.nobasecrl");
                    throw new certpathreviewerexception(msg);
                }
            }

            if (idp != null)
            {
                issuingdistributionpoint    p = issuingdistributionpoint.getinstance(idp);
                basicconstraints bc = null;
                try
                {
                    bc = basicconstraints.getinstance(getextensionvalue(cert, basic_constraints));
                }
                catch (annotatedexception ae)
                {
                    errorbundle msg = new errorbundle(resource_name,"certpathreviewer.crlbcexterror");
                    throw new certpathreviewerexception(msg,ae);
                }
                
                if (p.onlycontainsusercerts() && (bc != null && bc.isca()))
                {
                    errorbundle msg = new errorbundle(resource_name,"certpathreviewer.crlonlyusercert");
                    throw new certpathreviewerexception(msg);
                }
                
                if (p.onlycontainscacerts() && (bc == null || !bc.isca()))
                {
                    errorbundle msg = new errorbundle(resource_name,"certpathreviewer.crlonlycacert");
                    throw new certpathreviewerexception(msg);
                }
                
                if (p.onlycontainsattributecerts())
                {
                    errorbundle msg = new errorbundle(resource_name,"certpathreviewer.crlonlyattrcert");
                    throw new certpathreviewerexception(msg);
                }
            }
        }
        
        if (!validcrlfound)
        {
            errorbundle msg = new errorbundle(resource_name,"certpathreviewer.novalidcrlfound");
            throw new certpathreviewerexception(msg);
        }
    
    }
    
    protected vector getcrldisturls(crldistpoint crldistpoints)
    {
        vector urls = new vector();
        
        if (crldistpoints != null)
        {
            distributionpoint[] distpoints = crldistpoints.getdistributionpoints();
            for (int i = 0; i < distpoints.length; i++)
            {
                distributionpointname dp_name = distpoints[i].getdistributionpoint();
                if (dp_name.gettype() == distributionpointname.full_name)
                {
                    generalname[] generalnames = generalnames.getinstance(dp_name.getname()).getnames();
                    for (int j = 0; j < generalnames.length; j++)
                    {
                        if (generalnames[j].gettagno() == generalname.uniformresourceidentifier)
                        {
                            string url = ((deria5string) generalnames[j].getname()).getstring();
                            urls.add(url);
                        }
                    }
                }
            }
        }
        return urls;
    }
    
    protected vector getocspurls(authorityinformationaccess authinfoaccess)
    {
        vector urls = new vector();
        
        if (authinfoaccess != null)
        {
            accessdescription[] ads = authinfoaccess.getaccessdescriptions();
            for (int i = 0; i < ads.length; i++)
            {
                if (ads[i].getaccessmethod().equals(accessdescription.id_ad_ocsp))
                {
                    generalname name = ads[i].getaccesslocation();
                    if (name.gettagno() == generalname.uniformresourceidentifier)
                    {
                        string url = ((deria5string) name.getname()).getstring();
                        urls.add(url);
                    }
                }
            }
        }
        
        return urls;
    }
    
    private x509crl getcrl(string location) throws certpathreviewerexception
    {
        x509crl result = null;
        try
        {
            url url = new url(location);
            
            if (url.getprotocol().equals("http") || url.getprotocol().equals("https"))
            {
                httpurlconnection conn = (httpurlconnection) url.openconnection();
                conn.setusecaches(false);
                //conn.setconnecttimeout(2000);
                conn.setdoinput(true);
                conn.connect();
                if (conn.getresponsecode() == httpurlconnection.http_ok)
                {
                    certificatefactory cf = certificatefactory.getinstance("x.509","bc");
                    result = (x509crl) cf.generatecrl(conn.getinputstream());
                }
                else
                {
                    throw new exception(conn.getresponsemessage());
                }
            }
        }
        catch (exception e)
        {
            errorbundle msg = new errorbundle(resource_name,
                    "certpathreviewer.loadcrldistpointerror",
                    new object[] {new untrustedinput(location),
                                  e.getmessage(),e,e.getclass().getname()});
            throw new certpathreviewerexception(msg);
        }
        return result;
    }
    
    protected collection gettrustanchors(x509certificate cert, set trustanchors) throws certpathreviewerexception
    {
        collection trustcoll = new arraylist();
        iterator it = trustanchors.iterator();
        
        x509certselector certselectx509 = new x509certselector();

        try
        {
            certselectx509.setsubject(getencodedissuerprincipal(cert).getencoded());
            byte[] ext = cert.getextensionvalue(x509extensions.authoritykeyidentifier.getid());

            if (ext != null)
            {
                asn1octetstring oct = (asn1octetstring)asn1primitive.frombytearray(ext);
                authoritykeyidentifier authid = authoritykeyidentifier.getinstance(asn1primitive.frombytearray(oct.getoctets()));

                certselectx509.setserialnumber(authid.getauthoritycertserialnumber());
                byte[] keyid = authid.getkeyidentifier();
                if (keyid != null)
                {
                    certselectx509.setsubjectkeyidentifier(new deroctetstring(keyid).getencoded());
                }
            }
        }
        catch (ioexception ex)
        {
            errorbundle msg = new errorbundle(resource_name,"certpathreviewer.trustanchorissuererror");
            throw new certpathreviewerexception(msg);
        }

        while (it.hasnext())
        {
            trustanchor trust = (trustanchor) it.next();
            if (trust.gettrustedcert() != null)
            {
                if (certselectx509.match(trust.gettrustedcert()))
                {
                    trustcoll.add(trust);
                }
            }
            else if (trust.getcaname() != null && trust.getcapublickey() != null)
            {
                x500principal certissuer = getencodedissuerprincipal(cert);
                x500principal caname = new x500principal(trust.getcaname());
                if (certissuer.equals(caname))
                {
                    trustcoll.add(trust);
                }
            }
        }
        return trustcoll;
    }
}
