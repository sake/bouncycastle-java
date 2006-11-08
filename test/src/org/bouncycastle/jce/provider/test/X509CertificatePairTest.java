package org.bouncycastle.jce.provider.test;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.x509.X509CertificatePair;

import java.io.ByteArrayInputStream;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class X509CertificatePairTest
    extends SimpleTest
{
    public void performTest()
        throws Exception
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");

        X509Certificate rootCert = (X509Certificate)cf.generateCertificate(
                                        new ByteArrayInputStream(CertPathTest.rootCertBin));
        X509Certificate interCert = (X509Certificate)cf.generateCertificate(
                                         new ByteArrayInputStream(CertPathTest.interCertBin));
        X509Certificate finalCert = (X509Certificate)cf.generateCertificate(
                                          new ByteArrayInputStream(CertPathTest.finalCertBin));


        X509CertificatePair pair1 = new X509CertificatePair(rootCert, interCert);
        X509CertificatePair pair2 = new X509CertificatePair(rootCert, interCert);
        X509CertificatePair pair3 = new X509CertificatePair(interCert, finalCert);
        X509CertificatePair pair4 = new X509CertificatePair(rootCert, finalCert);

        if (!pair1.equals(pair2))
        {
            fail("pair1 pair2 equality test");
        }

        if (pair1.hashCode() != pair2.hashCode())
        {
            fail("pair1 pair2 hashCode equality test");
        }

        if (pair1.equals(pair3))
        {
            fail("pair1 pair3 inequality test");
        }

        if (pair1.equals(pair4))
        {
            fail("pair1 pair4 inequality test");
        }

        if (pair1.getForward() != rootCert)
        {
            fail("pair1 forward test");
        }

        if (pair1.getReverse() != interCert)
        {
            fail("pair1 reverse test");
        }

        if (!areEqual(pair1.getEncoded(), pair2.getEncoded()))
        {
            fail("encoding check");
        }

        X509CertificatePair pair5 = new X509CertificatePair(rootCert, TestUtils.createExceptionCertificate(false));

        try
        {
            pair5.getEncoded();

            fail("no exception on bad getEncoded()");
        }
        catch (CertificateEncodingException e)
        {
            // expected
        }

        pair4 = new X509CertificatePair(rootCert, TestUtils.createExceptionCertificate(true));

        try
        {
            pair4.getEncoded();

            fail("no exception on exception getEncoded()");
        }
        catch (CertificateEncodingException e)
        {
            // expected
        }
    }

    public String getName()
    {
        return "X509CertificatePair";
    }

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new X509CertificatePairTest());
    }

}
