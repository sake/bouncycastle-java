package org.bouncycastle.dvcs;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Collection;
import java.util.Date;
import java.util.GregorianCalendar;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.SignerInformationVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Store;

/**
 * DVCRequest and DVCResponse
 * are implemented in terms of this class,
 * as they are both coded in CMS
 */
public abstract class DVCMessage
{

    /**
     * ContentInfo ASN.1 structure, underlying DVCMessage.
     * (e.g. both DVCRequest and DVCResponse)
     */
    protected ContentInfo contentInfo;
    protected CMSSignedData signedData;

    /**
     * Parse DVCMessage from byte array.
     * Note: this constructor calls back to initDataStructure method of subtype.
     *
     * @param in - byte array
     * @throws DVCSException
     * @throws IOException
     */
    protected DVCMessage(byte[] in)
        throws DVCSException, IOException
    {
        this(ContentInfo.getInstance(in));
    }

    /**
     * Create DVCMessage from CMS ContentInfo ASN.1 structure.
     * Note: this constructor calls back to initDataStructure method of subtype.
     *
     * @param contentInfo
     * @throws DVCSException
     * @throws IOException
     */
    protected DVCMessage(ContentInfo contentInfo)
        throws DVCSException, IOException
    {
        this.contentInfo = contentInfo;
        this.signedData = getSignedData(contentInfo);
        init();
    }

    /**
     * Create DVCMessage from CMS SignedData object.
     * Note: this constructor calls back to initDataStructure method of subtype.
     *
     * @param signedData
     * @throws DVCSException
     * @throws IOException
     */
    protected DVCMessage(CMSSignedData signedData)
        throws DVCSException
    {
        this.signedData = signedData;
        this.contentInfo = signedData.toASN1Structure();
        init();
    }

    private static CMSSignedData getSignedData(ContentInfo contentInfo)
        throws DVCSException
    {
        try
        {
            return new CMSSignedData(contentInfo);
        }
        catch (CMSException e)
        {
            throw new DVCSException("CMS parsing error: " + e.getMessage(), e.getCause());
        }
    }

    private void init()
        throws DVCSException
    {
        // check type:
        {
            String typeOID = signedData.getSignedContentTypeOID();
            String needOID = getContentType().toString();
            if (!typeOID.equals(needOID))
            {
                throw new DVCSParsingException("ContentInfo contains not " + needOID + " but " + typeOID);
            }
        }

        // get content:
        ASN1InputStream aIn = null;
        try
        {
            CMSProcessable content = signedData.getSignedContent();
            ByteArrayOutputStream bOut = new ByteArrayOutputStream();
            content.write(bOut);
            this.initDataStructure(ASN1Primitive.fromByteArray(bOut.toByteArray()));
        }
        catch (CMSException e)
        {
            throw new DVCSInitializationException(e.getMessage(), e.getUnderlyingException());
        }
        catch (IOException e)
        {
            throw new DVCSInitializationException(e.getMessage(), e);
        }

    }

    /**
     * Subclasses should return the encapsulated content type in ContentInfo.
     * This enables DVCMessage to check its type.
     *
     * @return OID of content type.
     */
    protected abstract ASN1ObjectIdentifier getContentType();

    /**
     * This method is called back from DVCMessage constructor,
     * and enables subclasses to initialize their data structure.
     *
     * @param primitive - ASN.1 object of data structure
     */
    protected abstract void initDataStructure(ASN1Primitive primitive);

    /**
     * Get encapsulated ASN.1 structure (DVCSRequest or DVCSResponse).
     *
     * @return
     */
    public abstract ASN1Encodable getEncapsulatedASN1Structure();

    /**
     * Convert DVCMessage to ASN1Object (ContentInfo).
     *
     * @return ContentInfo ASN.1 object
     */
    public ContentInfo toASN1Object()
    {
        return contentInfo;
    }

    /**
     * Convert DVCMessage to CMS SignedData object.
     *
     * @return
     */
    public CMSSignedData toCMSSignedData()
    {
        return signedData;
    }

    /**
     * Encode DVCMessage in DER.
     *
     * @return DER encoding of DVCMessage.
     * @throws IOException
     */
    public byte[] getEncoded()
        throws IOException
    {
        return contentInfo.getEncoded();
    }

    @SuppressWarnings("unchecked")
    public boolean isSignatureValid(SignerInformationVerifierProvider prov)
        throws DVCSException
    {
        try
        {
            return this.signedData.verifySignatures(prov, true); // TODO: really ignore counter signatures?
        }
        catch (CMSException e)
        {
            throw new DVCSException(e.getMessage(), e.getCause());
        }
    }

    /**
     * Validate signature for specified verifier (signer).
     *
     * @param sigInfoVerifier
     * @return
     */
    public boolean isSignatureValid(SignerInformationVerifier sigInfoVerifier)
    {
        X509CertificateHolder cert = sigInfoVerifier.getAssociatedCertificate();
        SignerId sid = new SignerId(cert.getIssuer(), cert.getSerialNumber());
        SignerInformation sigInfo = signedData.getSignerInfos().get(sid);

        if (sigInfo == null)
        {
            return false;
        }

        try
        {
            return sigInfo.verify(sigInfoVerifier);
        }
        catch (CMSException e)
        {
            return false;
        }
    }

    @SuppressWarnings("unchecked")
    protected X509CertificateHolder getCertificate(Store additionalCerts, SignerId sid)
    {
        // search in SignedData store:
        Collection<X509CertificateHolder> certs = signedData.getCertificates().getMatches(sid);

        // and in additional certificates:
        certs.addAll(additionalCerts.getMatches(sid));

        // now look for the up-to-date certificate:
        Date now = new GregorianCalendar().getTime();
        for (X509CertificateHolder cert : certs)
        {
            if (cert.isValidOn(now))
            {
                return cert;
            }
        }

        return null;
    }

    /**
     * Gets collection of certificates in DVCRequest (DVCResponse).
     * Further, this store can be searched by selectors, obtained by CertInfo.getSelector().
     * (see RFC 3029, 7.5)
     *
     * @return Store of certificates in DVCMessage (DVCRequest or DVCResponse)
     */
    @SuppressWarnings("unchecked")
    public Collection<X509CertificateHolder> getCertificates()
    {
        return signedData.getCertificates().getMatches(null);
    }

    public String toString()
    {
        return this.getEncapsulatedASN1Structure().toString();
    }

}
