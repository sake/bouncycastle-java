package org.bouncycastle.cert.crmf.jcajce;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.Provider;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.crmf.CRMFException;
import org.bouncycastle.cert.crmf.PKMACValuesCalculator;

public class JcaPKMACValuesCalculator
    implements PKMACValuesCalculator
{
    private MessageDigest digest;
    private Mac           mac;
    private CRMFHelper    helper;

    public JcaPKMACValuesCalculator()
    {
        this.helper = new DefaultCRMFHelper();
    }

    public JcaPKMACValuesCalculator setProvider(Provider provider)
    {
        this.helper = new ProviderCRMFHelper(provider);

        return this;
    }

    public JcaPKMACValuesCalculator setProvider(String providerName)
    {
        this.helper = new NamedCRMFHelper(providerName);

        return this;
    }

    public void setup(AlgorithmIdentifier digAlg, AlgorithmIdentifier macAlg)
        throws CRMFException
    {
        digest = helper.createDigest(digAlg.getAlgorithm());
        mac = helper.createMac(macAlg.getAlgorithm());
    }

    public byte[] calculateDigest(byte[] data)
    {
        return digest.digest(data);
    }

    public byte[] calculateMac(byte[] pwd, byte[] data)
        throws CRMFException
    {
        try
        {
            mac.init(new SecretKeySpec(pwd, "HMacSHA1"));

            return mac.doFinal(data);
        }
        catch (GeneralSecurityException e)
        {
            throw new CRMFException("failure in setup: " + e.getMessage(), e);
        }
    }
}
