package org.bouncycastle.cms.test;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.util.encoders.Base64;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;

public class EnvelopedDataTest
    extends TestCase 
{
    private static String          _signDN;
    private static KeyPair         _signKP;  
    private static X509Certificate _signCert;

    private static String          _origDN;
    private static KeyPair         _origKP;
    private static X509Certificate _origCert;

    private static String          _reciDN;
    private static KeyPair         _reciKP;
    private static X509Certificate _reciCert;
    
    private static boolean         _initialised = false;

    private byte[] oldKEK = Base64.decode(
                          "MIAGCSqGSIb3DQEHA6CAMIACAQIxQaI/MD0CAQQwBwQFAQIDBAUwDQYJYIZIAWUDBAEFBQAEI"
                        + "Fi2eHTPM4bQSjP4DUeDzJZLpfemW2gF1SPq7ZPHJi1mMIAGCSqGSIb3DQEHATAUBggqhkiG9w"
                        + "0DBwQImtdGyUdGGt6ggAQYk9X9z01YFBkU7IlS3wmsKpm/zpZClTceAAAAAAAAAAAAAA==");

    private byte[] ecKeyAgreeMsg = Base64.decode(
                          "MIAGCSqGSIb3DQEHA6CAMIACAQIxgbyhgbkCAQOgKKEmMAsGByqGSM49AgEF"
                        + "AAMXAAMA1MeMnJtKgJzEaQlORe8fog2gDiMwGgYJK4EFEIZIPwACMA0GCWCG"
                        + "SAFlAwQBLQUAMG4wbDBAMDQxDDAKBgNVBAMMA2NuMTEKMAgGA1UECgwBbzEL"
                        + "MAkGA1UECwwCb3UxCzAJBgNVBAYMAmNhAghyzkH+vWY1OwQo3IEM2H+9E64C"
                        + "33KFP8j1aahAvWkyA4NVkIRAuivjKxE96Szy7ugH1DCABgkqhkiG9w0BBwEw"
                        + "HQYJYIZIAWUDBAEqBBAJ72q+1QnJ+62gouQaU6mnoIAEIFIdsc9qBCEOi9kk"
                        + "JcNSQ+2QzdtoEq1ViybBhek+ubdbBBCHqu8xycnrhY6RZ5F7KVdfAAAAAAAA"
                        + "AAAAAA==");

    private byte[] ecKeyAgreeKey = Base64.decode(
                          "MIGkAgEBBDCQ7Fw/nnkISP0hSf8Z4FL66Zhv6MBBvhKK9lZFkbXKoxRBBnqQrb7Y"
                        + "dKaeKf1ywyOgBwYFK4EEACKhZANiAgSwM/xU6jA6/eKVlpceGlngGyVC/mhTzfeM"
                        + "VB6Sih6P6rzdR2cBtQDIfpU555Q5FJTzfvki+H57PIFtx0o82dnzgG8UGKZci25Y"
                        + "qswDRAfnTE3q/3pknY9DjZtwBbYCabQ=");

    public EnvelopedDataTest()
    {
    }

    private static void init()
        throws Exception
    {
        if (!_initialised)
        {
            _initialised = true;
            
            _signDN   = "O=Bouncy Castle, C=AU";
            _signKP   = CMSTestUtil.makeKeyPair();  
            _signCert = CMSTestUtil.makeCertificate(_signKP, _signDN, _signKP, _signDN);

            _origDN   = "CN=Bob, OU=Sales, O=Bouncy Castle, C=AU";
            _origKP   = CMSTestUtil.makeKeyPair();
            _origCert = CMSTestUtil.makeCertificate(_origKP, _origDN, _signKP, _signDN);

            _reciDN   = "CN=Doug, OU=Sales, O=Bouncy Castle, C=AU";
            _reciKP   = CMSTestUtil.makeKeyPair();
            _reciCert = CMSTestUtil.makeCertificate(_reciKP, _reciDN, _signKP, _signDN);      
        }
    }
    
    public static void main(
        String args[]) 
    {
        junit.textui.TestRunner.run(EnvelopedDataTest.class);
    }

    public static Test suite() 
        throws Exception
    {
        init();
        
        return new CMSTestSetup(new TestSuite(EnvelopedDataTest.class));
    }

    public void testKeyTrans()
        throws Exception
    {
        byte[]          data     = "WallaWallaWashington".getBytes();

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        edGen.addKeyTransRecipient(_reciCert);

        CMSEnvelopedData ed = edGen.generate(
                                new CMSProcessableByteArray(data),
                                CMSEnvelopedDataGenerator.DES_EDE3_CBC, "BC");

        RecipientInformationStore  recipients = ed.getRecipientInfos();


        assertEquals(ed.getEncryptionAlgOID(), CMSEnvelopedDataGenerator.DES_EDE3_CBC);
        
        Collection  c = recipients.getRecipients();
        Iterator    it = c.iterator();

        while (it.hasNext())
        {
            RecipientInformation   recipient = (RecipientInformation)it.next();

            assertEquals(recipient.getKeyEncryptionAlgOID(), PKCSObjectIdentifiers.rsaEncryption.getId());
            
            byte[] recData = recipient.getContent(_reciKP.getPrivate(), "BC");

            assertEquals(true, Arrays.equals(data, recData));
        }
    }

    public void testKeyTransAES128()
        throws Exception
    {
        byte[]          data     = "WallaWallaWashington".getBytes();

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        edGen.addKeyTransRecipient(_reciCert);

        CMSEnvelopedData ed = edGen.generate(
                                new CMSProcessableByteArray(data),
                                CMSEnvelopedDataGenerator.AES128_CBC, "BC");

        RecipientInformationStore  recipients = ed.getRecipientInfos();

        assertEquals(ed.getEncryptionAlgOID(), CMSEnvelopedDataGenerator.AES128_CBC);
        
        Collection  c = recipients.getRecipients();
        Iterator    it = c.iterator();
        
        while (it.hasNext())
        {
            RecipientInformation   recipient = (RecipientInformation)it.next();

            assertEquals(recipient.getKeyEncryptionAlgOID(), PKCSObjectIdentifiers.rsaEncryption.getId());
            
            byte[] recData = recipient.getContent(_reciKP.getPrivate(), "BC");

            assertEquals(true, Arrays.equals(data, recData));
        }
    }

    public void testKeyTransCAST5SunJCE()
        throws Exception
    {
        if (Security.getProvider("SunJCE") == null)
        {
            return;
        }
        
        String version = System.getProperty("java.version");
        if (version.startsWith("1.4") || version.startsWith("1.3"))
        {
            return;
        }
        
        byte[]          data     = "WallaWallaWashington".getBytes();
    
        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();
    
        edGen.addKeyTransRecipient(_reciCert);

        CMSEnvelopedData ed = edGen.generate(
                                new CMSProcessableByteArray(data),
                                CMSEnvelopedDataGenerator.CAST5_CBC, "SunJCE");
        RecipientInformationStore  recipients = ed.getRecipientInfos();
        
        assertEquals(ed.getEncryptionAlgOID(), CMSEnvelopedDataGenerator.CAST5_CBC);

        Collection  c = recipients.getRecipients();
        Iterator    it = c.iterator();
        
        while (it.hasNext())
        {
            RecipientInformation   recipient = (RecipientInformation)it.next();
    
            assertEquals(recipient.getKeyEncryptionAlgOID(), PKCSObjectIdentifiers.rsaEncryption.getId());
            
            byte[] recData = recipient.getContent(_reciKP.getPrivate(), "SunJCE");
    
            assertEquals(true, Arrays.equals(data, recData));
        }
    }
    
    public void testKeyTransAES192()
        throws Exception
    {
        byte[]          data     = "WallaWallaWashington".getBytes();

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        edGen.addKeyTransRecipient(_reciCert);

        CMSEnvelopedData ed = edGen.generate(
                                new CMSProcessableByteArray(data),
                                CMSEnvelopedDataGenerator.AES192_CBC, "BC");

        RecipientInformationStore  recipients = ed.getRecipientInfos();

        assertEquals(ed.getEncryptionAlgOID(), CMSEnvelopedDataGenerator.AES192_CBC);
        
        Collection  c = recipients.getRecipients();
        Iterator    it = c.iterator();

        while (it.hasNext())
        {
            RecipientInformation   recipient = (RecipientInformation)it.next();

            assertEquals(recipient.getKeyEncryptionAlgOID(), PKCSObjectIdentifiers.rsaEncryption.getId());
            
            byte[] recData = recipient.getContent(_reciKP.getPrivate(), "BC");

            assertEquals(true, Arrays.equals(data, recData));
        }
    }

    public void testKeyTransAES256()
        throws Exception
    {
        byte[]          data     = "WallaWallaWashington".getBytes();

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        edGen.addKeyTransRecipient(_reciCert);

        CMSEnvelopedData ed = edGen.generate(
                                new CMSProcessableByteArray(data),
                                CMSEnvelopedDataGenerator.AES256_CBC, "BC");

        RecipientInformationStore  recipients = ed.getRecipientInfos();

        assertEquals(ed.getEncryptionAlgOID(), "2.16.840.1.101.3.4.1.42");
        
        Collection  c = recipients.getRecipients();
        Iterator    it = c.iterator();

        while (it.hasNext())
        {
            RecipientInformation   recipient = (RecipientInformation)it.next();

            byte[] recData = recipient.getContent(_reciKP.getPrivate(), "BC");

            assertEquals(true, Arrays.equals(data, recData));
        }
    }

    public void testKeyTransRC4()
        throws Exception
    {
        byte[]          data     = "WallaWallaBouncyCastle".getBytes();

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        edGen.addKeyTransRecipient(_reciCert);

        CMSEnvelopedData ed = edGen.generate(
                                new CMSProcessableByteArray(data),
                                "1.2.840.113549.3.4", "BC");

        RecipientInformationStore  recipients = ed.getRecipientInfos();

        assertEquals(ed.getEncryptionAlgOID(), "1.2.840.113549.3.4");
        
        Collection  c = recipients.getRecipients();
        Iterator    it = c.iterator();

        while (it.hasNext())
        {
            RecipientInformation   recipient = (RecipientInformation)it.next();

            byte[] recData = recipient.getContent(_reciKP.getPrivate(), "BC");

            assertEquals(true, Arrays.equals(data, recData));
        }
    }
    
    public void testKeyTrans128RC4()
        throws Exception
    {
        byte[]          data     = "WallaWallaBouncyCastle".getBytes();

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        edGen.addKeyTransRecipient(_reciCert);

        CMSEnvelopedData ed = edGen.generate(
                                new CMSProcessableByteArray(data),
                                "1.2.840.113549.3.4", 128, "BC");

        RecipientInformationStore  recipients = ed.getRecipientInfos();

        assertEquals(ed.getEncryptionAlgOID(), "1.2.840.113549.3.4");
        
        Collection  c = recipients.getRecipients();
        Iterator    it = c.iterator();

        while (it.hasNext())
        {
            RecipientInformation   recipient = (RecipientInformation)it.next();

            byte[] recData = recipient.getContent(_reciKP.getPrivate(), "BC");

            assertEquals(true, Arrays.equals(data, recData));
        }
    }
    
    public void testKeyTransODES()
        throws Exception
    {
        byte[]          data     = "WallaWallaBouncyCastle".getBytes();

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        edGen.addKeyTransRecipient(_reciCert);

        CMSEnvelopedData ed = edGen.generate(
                                new CMSProcessableByteArray(data),
                                "1.3.14.3.2.7", "BC");

        RecipientInformationStore  recipients = ed.getRecipientInfos();

        assertEquals(ed.getEncryptionAlgOID(), "1.3.14.3.2.7");
        
        Collection  c = recipients.getRecipients();
        Iterator    it = c.iterator();

        while (it.hasNext())
        {
            RecipientInformation   recipient = (RecipientInformation)it.next();

            byte[] recData = recipient.getContent(_reciKP.getPrivate(), "BC");

            assertEquals(true, Arrays.equals(data, recData));
        }
    }

    public void testKeyTransSmallAES()
        throws Exception
    {
        byte[]          data     = new byte[] { 0, 1, 2, 3 };

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        edGen.addKeyTransRecipient(_reciCert);

        CMSEnvelopedData ed = edGen.generate(
                              new CMSProcessableByteArray(data),
                              CMSEnvelopedDataGenerator.AES128_CBC, "BC");

        RecipientInformationStore  recipients = ed.getRecipientInfos();

        assertEquals(ed.getEncryptionAlgOID(),
                                   CMSEnvelopedDataGenerator.AES128_CBC);
        
        Collection  c = recipients.getRecipients();
        Iterator    it = c.iterator();

        while (it.hasNext())
        {
            RecipientInformation   recipient = (RecipientInformation)it.next();

            byte[] recData = recipient.getContent(_reciKP.getPrivate(), "BC");
            assertEquals(true, Arrays.equals(data, recData));
        }
    }

    public void testDESKEK()
        throws Exception
    {
        byte[]    data = "WallaWallaWashington".getBytes();
        SecretKey kek  = CMSTestUtil.makeDesede192Key();
        
        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        byte[]  kekId = new byte[] { 1, 2, 3, 4, 5 };

        edGen.addKEKRecipient(kek, kekId);

        CMSEnvelopedData ed = edGen.generate(
                                new CMSProcessableByteArray(data),
                                CMSEnvelopedDataGenerator.DES_EDE3_CBC, "BC");

        RecipientInformationStore  recipients = ed.getRecipientInfos();

        assertEquals(ed.getEncryptionAlgOID(), CMSEnvelopedDataGenerator.DES_EDE3_CBC);
        
        Collection  c = recipients.getRecipients();
        Iterator    it = c.iterator();

        while (it.hasNext())
        {
            RecipientInformation   recipient = (RecipientInformation)it.next();

            assertEquals(recipient.getKeyEncryptionAlgOID(), "1.2.840.113549.1.9.16.3.6");
            
            byte[] recData = recipient.getContent(kek, "BC");

            assertEquals(true, Arrays.equals(data, recData));
        }
    }

    public void testErrorneousKEK()
        throws Exception
    {
        byte[]    data = "WallaWallaWashington".getBytes();
        SecretKey kek  = new SecretKeySpec(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 }, "AES");

        CMSEnvelopedData ed = new CMSEnvelopedData(oldKEK);

        RecipientInformationStore  recipients = ed.getRecipientInfos();

        assertEquals(ed.getEncryptionAlgOID(), CMSEnvelopedDataGenerator.DES_EDE3_CBC);

        Collection  c = recipients.getRecipients();
        Iterator    it = c.iterator();

        while (it.hasNext())
        {
            RecipientInformation   recipient = (RecipientInformation)it.next();

            assertEquals(recipient.getKeyEncryptionAlgOID(), NISTObjectIdentifiers.id_aes128_wrap.getId());

            byte[] recData = recipient.getContent(kek, "BC");

            assertEquals(true, Arrays.equals(data, recData));
        }
    }

    public void testAESKEK()
        throws Exception
    {
        byte[]    data = "WallaWallaWashington".getBytes();
        SecretKey kek  = CMSTestUtil.makeAES192Key();
        
        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        byte[]  kekId = new byte[] { 1, 2, 3, 4, 5 };

        edGen.addKEKRecipient(kek, kekId);

        CMSEnvelopedData ed = edGen.generate(
                                new CMSProcessableByteArray(data),
                                CMSEnvelopedDataGenerator.DES_EDE3_CBC, "BC");

        RecipientInformationStore  recipients = ed.getRecipientInfos();

        assertEquals(ed.getEncryptionAlgOID(), CMSEnvelopedDataGenerator.DES_EDE3_CBC);
        
        Collection  c = recipients.getRecipients();
        Iterator    it = c.iterator();

        while (it.hasNext())
        {
            RecipientInformation   recipient = (RecipientInformation)it.next();

            assertEquals(recipient.getKeyEncryptionAlgOID(), "2.16.840.1.101.3.4.1.25");
            
            byte[] recData = recipient.getContent(kek, "BC");

            assertEquals(true, Arrays.equals(data, recData));
        }
    }

    public void testRC2KEK()
        throws Exception
    {
        byte[]    data = "WallaWallaWashington".getBytes();
        SecretKey kek  = CMSTestUtil.makeRC2128Key();
        
        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        byte[]  kekId = new byte[] { 1, 2, 3, 4, 5 };

        edGen.addKEKRecipient(kek, kekId);

        CMSEnvelopedData ed = edGen.generate(
                                new CMSProcessableByteArray(data),
                                CMSEnvelopedDataGenerator.DES_EDE3_CBC, "BC");

        RecipientInformationStore  recipients = ed.getRecipientInfos();

        Collection  c = recipients.getRecipients();
        Iterator    it = c.iterator();

        assertEquals(ed.getEncryptionAlgOID(), CMSEnvelopedDataGenerator.DES_EDE3_CBC);
        
        while (it.hasNext())
        {
            RecipientInformation   recipient = (RecipientInformation)it.next();

            assertEquals(recipient.getKeyEncryptionAlgOID(), "1.2.840.113549.1.9.16.3.7");
            
            byte[] recData = recipient.getContent(kek, "BC");

            assertEquals(true, Arrays.equals(data, recData));
        }
    }

   public void testECKeyAgree()
        throws Exception
    {
        CMSEnvelopedData ed = new CMSEnvelopedData(ecKeyAgreeMsg);

        RecipientInformationStore  recipients = ed.getRecipientInfos();

        Collection  c = recipients.getRecipients();
        Iterator    it = c.iterator();

        assertEquals(ed.getEncryptionAlgOID(), "2.16.840.1.101.3.4.1.42");

//        ECPrivateKeyStructure pKey = new ECPrivateKeyStructure((ASN1Sequence)ASN1Object.fromByteArray(ecKeyAgreeKey));
//        AlgorithmIdentifier algId = new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, pKey.getParameters());
//        PrivateKeyInfo privInfo = new PrivateKeyInfo(algId, pKey.getDERObject());
//        PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(privInfo.getEncoded());
//        KeyFactory            fact = KeyFactory.getInstance("ECDH", "BC");
//
//        while (it.hasNext())
//        {
//            RecipientInformation   recipient = (RecipientInformation)it.next();
//
//            //assertEquals(recipient.getKeyEncryptionAlgOID(), "1.2.840.113549.3.7");
//
//            byte[] recData = recipient.getContent(fact.generatePrivate(privSpec), "BC");
//            System.out.println(new String(recData));
////
////            byte[] recData = recipient.getContent(kek, "BC");
////
////            assertEquals(true, Arrays.equals(data, recData));
//        }
    }
}
