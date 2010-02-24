package org.bouncycastle.openssl;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.Reader;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.StringTokenizer;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ParsingException;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.EncryptionScheme;
import org.bouncycastle.asn1.pkcs.KeyDerivationFunc;
import org.bouncycastle.asn1.pkcs.PBES2Parameters;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.sec.ECPrivateKeyStructure;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.RSAPublicKeyStructure;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemObjectParser;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.x509.X509V2AttributeCertificate;

/**
 * Class for reading OpenSSL PEM encoded streams containing
 * X509 certificates, PKCS8 encoded keys and PKCS7 objects.
 * <p/>
 * In the case of PKCS7 objects the reader will return a CMS ContentInfo object. Keys and
 * Certificates will be returned using the appropriate java.security type.
 */
public class PEMReader
    extends PemReader
{
    private final Map parsers = new HashMap();

    private final PasswordFinder pFinder;

    /**
     * Create a new PEMReader
     *
     * @param reader the Reader
     */
    public PEMReader(
        Reader reader)
    {
        this(reader, null, "BC");
    }

    /**
     * Create a new PEMReader with a password finder
     *
     * @param reader  the Reader
     * @param pFinder the password finder
     */
    public PEMReader(
        Reader reader,
        PasswordFinder pFinder)
    {
        this(reader, pFinder, "BC");
    }

    /**
     * Create a new PEMReader with a password finder
     *
     * @param reader   the Reader
     * @param pFinder  the password finder
     * @param provider the cryptography provider to use
     */
    public PEMReader(
        Reader reader,
        PasswordFinder pFinder,
        String provider)
    {
        super(reader);

        this.pFinder = pFinder;

        parsers.put("CERTIFICATE REQUEST", new PKCS10CertificationRequestParser());
        parsers.put("NEW CERTIFICATE REQUEST", new PKCS10CertificationRequestParser());
        parsers.put("CERTIFICATE", new X509CertificateParser(provider));
        parsers.put("X509 CERTIFICATE", new X509CertificateParser(provider));
        parsers.put("X509 CRL", new X509CRLParser(provider));
        parsers.put("PKCS7", new PKCS7Parser());
        parsers.put("ATTRIBUTE CERTIFICATE", new X509AttributeCertificateParser());
        parsers.put("EC PARAMETERS", new ECNamedCurveSpecParser());
        parsers.put("PUBLIC KEY", new PublicKeyParser(provider));
        parsers.put("RSA PUBLIC KEY", new RSAPublicKeyParser(provider));
        parsers.put("RSA PRIVATE KEY", new RSAKeyPairParser(provider));
        parsers.put("DSA PRIVATE KEY", new DSAKeyPairParser(provider));
        parsers.put("EC PRIVATE KEY", new ECDSAKeyPairParser(provider));
        parsers.put("ENCRYPTED PRIVATE KEY", new EncryptedPrivateKeyParser(provider));
    }

    public Object readObject()
        throws IOException
    {
        PemObject obj = readPemObject();

        if (obj != null)
        {
            String type = obj.getType();
            if (parsers.containsKey(type))
            {
                return ((PemObjectParser)parsers.get(type)).parseObject(obj);
            }
            else
            {
                throw new IOException("unrecognised object: " + type);
            }
        }

        return null;
    }

    private abstract class KeyPairParser
        implements PemObjectParser
    {
        protected String provider;

        public KeyPairParser(String provider)
        {
            this.provider = provider;
        }

        /**
         * Read a Key Pair
         */
        protected ASN1Sequence readKeyPair(
            PemObject obj)
            throws IOException
        {
            boolean isEncrypted = false;
            String dekInfo = null;
            Map headers = obj.getHeaders();

            for (Iterator it = headers.keySet().iterator(); it.hasNext();)
            {
                String hdr = (String)it.next();

                if (hdr.equals("Proc-Type") && headers.get(hdr).equals("4,ENCRYPTED"))
                {
                    isEncrypted = true;
                }
                else if (hdr.equals("DEK-Info"))
                {
                    dekInfo = (String)headers.get(hdr);
                }
            }

            //
            // extract the key
            //
            byte[] keyBytes = obj.getContent();

            if (isEncrypted)
            {
                if (pFinder == null)
                {
                    throw new PasswordException("No password finder specified, but a password is required");
                }

                char[] password = pFinder.getPassword();

                if (password == null)
                {
                    throw new PasswordException("Password is null, but a password is required");
                }

                StringTokenizer tknz = new StringTokenizer(dekInfo, ",");
                String dekAlgName = tknz.nextToken();
                byte[] iv = Hex.decode(tknz.nextToken());

                keyBytes = PEMUtilities.crypt(false, provider, keyBytes, password, dekAlgName, iv);
            }

            try
            {
                return (ASN1Sequence)ASN1Object.fromByteArray(keyBytes);
            }
            catch (ASN1ParsingException e)
            {
                throw new PEMException(e.getMessage(), e);
            }
        }
    }

    private class DSAKeyPairParser
        extends KeyPairParser
    {
        public DSAKeyPairParser(String provider)
        {
            super(provider);
        }

        public Object parseObject(PemObject obj)
            throws IOException
        {
            ASN1Sequence seq = readKeyPair(obj);

            //            DERInteger              v = (DERInteger)seq.getObjectAt(0);
            DERInteger p = (DERInteger)seq.getObjectAt(1);
            DERInteger q = (DERInteger)seq.getObjectAt(2);
            DERInteger g = (DERInteger)seq.getObjectAt(3);
            DERInteger y = (DERInteger)seq.getObjectAt(4);
            DERInteger x = (DERInteger)seq.getObjectAt(5);

            DSAPrivateKeySpec privSpec = new DSAPrivateKeySpec(
                x.getValue(), p.getValue(),
                q.getValue(), g.getValue());
            DSAPublicKeySpec pubSpec = new DSAPublicKeySpec(
                y.getValue(), p.getValue(),
                q.getValue(), g.getValue());

            try
            {
                KeyFactory fact = KeyFactory.getInstance("DSA", provider);


                return new KeyPair(
                    fact.generatePublic(pubSpec),
                    fact.generatePrivate(privSpec));
            }
            catch (Exception e)
            {
                throw new PEMException(
                    "problem creating DSA private key: " + e.toString(), e);
            }
        }
    }

    private class ECDSAKeyPairParser
        extends KeyPairParser
    {
        public ECDSAKeyPairParser(String provider)
        {
            super(provider);
        }

        public Object parseObject(PemObject obj)
            throws IOException
        {
            ASN1Sequence seq = readKeyPair(obj);

            ECPrivateKeyStructure pKey = new ECPrivateKeyStructure(seq);
            AlgorithmIdentifier algId = new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, pKey.getParameters());
            PrivateKeyInfo privInfo = new PrivateKeyInfo(algId, pKey.getDERObject());
            SubjectPublicKeyInfo pubInfo = new SubjectPublicKeyInfo(algId, pKey.getPublicKey().getBytes());

            PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(privInfo.getEncoded());
            X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(pubInfo.getEncoded());

            try
            {
                KeyFactory fact = KeyFactory.getInstance("ECDSA", provider);


                return new KeyPair(
                    fact.generatePublic(pubSpec),
                    fact.generatePrivate(privSpec));
            }
            catch (Exception e)
            {
                throw new PEMException(
                    "problem creating EC private key: " + e.toString(), e);
            }
        }
    }

    private class RSAKeyPairParser
        extends KeyPairParser
    {
        public RSAKeyPairParser(String provider)
        {
            super(provider);
        }

        public Object parseObject(PemObject obj)
            throws IOException
        {
            ASN1Sequence seq = readKeyPair(obj);

            //            DERInteger              v = (DERInteger)seq.getObjectAt(0);
            DERInteger mod = (DERInteger)seq.getObjectAt(1);
            DERInteger pubExp = (DERInteger)seq.getObjectAt(2);
            DERInteger privExp = (DERInteger)seq.getObjectAt(3);
            DERInteger p1 = (DERInteger)seq.getObjectAt(4);
            DERInteger p2 = (DERInteger)seq.getObjectAt(5);
            DERInteger exp1 = (DERInteger)seq.getObjectAt(6);
            DERInteger exp2 = (DERInteger)seq.getObjectAt(7);
            DERInteger crtCoef = (DERInteger)seq.getObjectAt(8);

            RSAPublicKeySpec pubSpec = new RSAPublicKeySpec(
                mod.getValue(), pubExp.getValue());
            RSAPrivateCrtKeySpec privSpec = new RSAPrivateCrtKeySpec(
                mod.getValue(), pubExp.getValue(), privExp.getValue(),
                p1.getValue(), p2.getValue(),
                exp1.getValue(), exp2.getValue(),
                crtCoef.getValue());

            try
            {
                KeyFactory fact = KeyFactory.getInstance("RSA", provider);


                return new KeyPair(
                    fact.generatePublic(pubSpec),
                    fact.generatePrivate(privSpec));
            }
            catch (Exception e)
            {
                throw new PEMException(
                    "problem creating RSA private key: " + e.toString(), e);
            }
        }
    }

    private class PublicKeyParser
        implements PemObjectParser
    {
        private String provider;

        public PublicKeyParser(String provider)
        {
            this.provider = provider;
        }

        public Object parseObject(PemObject obj)
            throws IOException
        {
            KeySpec keySpec = new X509EncodedKeySpec(obj.getContent());
            String[] algorithms = {"DSA", "RSA"};
            for (int i = 0; i < algorithms.length; i++)
            {
                try
                {
                    KeyFactory keyFact = KeyFactory.getInstance(algorithms[i], provider);
                    PublicKey pubKey = keyFact.generatePublic(keySpec);

                    return pubKey;
                }
                catch (NoSuchAlgorithmException e)
                {
                    // ignore
                }
                catch (InvalidKeySpecException e)
                {
                    // ignore
                }
                catch (NoSuchProviderException e)
                {
                    throw new RuntimeException("can't find provider " + provider);
                }
            }

            return null;
        }
    }

    private class RSAPublicKeyParser
        implements PemObjectParser
    {
        private String provider;

        public RSAPublicKeyParser(String provider)
        {
            this.provider = provider;
        }

        public Object parseObject(PemObject obj)
            throws IOException
        {
            ASN1InputStream ais = new ASN1InputStream(obj.getContent());
            Object asnObject = ais.readObject();
            ASN1Sequence sequence = (ASN1Sequence)asnObject;
            RSAPublicKeyStructure rsaPubStructure = new RSAPublicKeyStructure(sequence);
            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(
                rsaPubStructure.getModulus(),
                rsaPubStructure.getPublicExponent());

            try
            {
                KeyFactory keyFact = KeyFactory.getInstance("RSA", provider);

                return keyFact.generatePublic(keySpec);
            }
            catch (NoSuchProviderException e)
            {
                throw new IOException("can't find provider " + provider);
            }
            catch (Exception e)
            {
                throw new PEMException("problem extracting key: " + e.toString(), e);
            }
        }
    }

    private class X509CertificateParser
        implements PemObjectParser
    {
        private String provider;

        public X509CertificateParser(String provider)
        {
            this.provider = provider;
        }

        /**
         * Reads in a X509Certificate.
         *
         * @return the X509Certificate
         * @throws IOException if an I/O error occured
         */
        public Object parseObject(PemObject obj)
            throws IOException
        {
            ByteArrayInputStream bIn = new ByteArrayInputStream(obj.getContent());

            try
            {
                CertificateFactory certFact
                    = CertificateFactory.getInstance("X.509", provider);

                return certFact.generateCertificate(bIn);
            }
            catch (Exception e)
            {
                throw new PEMException("problem parsing cert: " + e.toString(), e);
            }
        }
    }

    private class X509CRLParser
        implements PemObjectParser
    {
        private String provider;

        public X509CRLParser(String provider)
        {
            this.provider = provider;
        }

        /**
         * Reads in a X509CRL.
         *
         * @return the X509Certificate
         * @throws IOException if an I/O error occured
         */
        public Object parseObject(PemObject obj)
            throws IOException
        {
            ByteArrayInputStream bIn = new ByteArrayInputStream(obj.getContent());

            try
            {
                CertificateFactory certFact
                    = CertificateFactory.getInstance("X.509", provider);

                return certFact.generateCRL(bIn);
            }
            catch (Exception e)
            {
                throw new PEMException("problem parsing cert: " + e.toString(), e);
            }
        }
    }

    private class PKCS10CertificationRequestParser
        implements PemObjectParser
    {
        /**
         * Reads in a PKCS10 certification request.
         *
         * @return the certificate request.
         * @throws IOException if an I/O error occured
         */
        public Object parseObject(PemObject obj)
            throws IOException
        {
            try
            {
                return new PKCS10CertificationRequest(obj.getContent());
            }
            catch (Exception e)
            {
                throw new PEMException("problem parsing certrequest: " + e.toString(), e);
            }
        }
    }

    private class PKCS7Parser
        implements PemObjectParser
    {
        /**
         * Reads in a PKCS7 object. This returns a ContentInfo object suitable for use with the CMS
         * API.
         *
         * @return the X509Certificate
         * @throws IOException if an I/O error occured
         */
        public Object parseObject(PemObject obj)
            throws IOException
        {
            try
            {
                ASN1InputStream aIn = new ASN1InputStream(obj.getContent());

                return ContentInfo.getInstance(aIn.readObject());
            }
            catch (Exception e)
            {
                throw new PEMException("problem parsing PKCS7 object: " + e.toString(), e);
            }
        }
    }

    private class X509AttributeCertificateParser
        implements PemObjectParser
    {
        public Object parseObject(PemObject obj)
            throws IOException
        {
            return new X509V2AttributeCertificate(obj.getContent());
        }
    }

    private class ECNamedCurveSpecParser
        implements PemObjectParser
    {
        public Object parseObject(PemObject obj)
            throws IOException
        {
            DERObjectIdentifier oid = (DERObjectIdentifier)ASN1Object.fromByteArray(obj.getContent());

            return ECNamedCurveTable.getParameterSpec(oid.getId());
        }
    }

    private class EncryptedPrivateKeyParser
        implements PemObjectParser
    {
        private String provider;

        public EncryptedPrivateKeyParser(String provider)
        {
            this.provider = provider;
        }

        /**
         * Reads in a X509CRL.
         *
         * @return the X509Certificate
         * @throws IOException if an I/O error occured
         */
        public Object parseObject(PemObject obj)
            throws IOException
        {
            EncryptedPrivateKeyInfo info = EncryptedPrivateKeyInfo.getInstance(ASN1Object.fromByteArray(obj.getContent()));
            AlgorithmIdentifier algId = info.getEncryptionAlgorithm();
            PBES2Parameters     params = PBES2Parameters.getInstance(algId.getParameters());
            KeyDerivationFunc   func = params.getKeyDerivationFunc();
            EncryptionScheme    scheme = params.getEncryptionScheme();
            PBKDF2Params        defParams = (PBKDF2Params)func.getParameters();

            PBEKeySpec pbeSpec = new PBEKeySpec(pFinder.getPassword(),
                defParams.getSalt(),
                defParams.getIterationCount().intValue(),
                256);   // TODO: get from algorithm name

            try
            {
                int     iterationCount = defParams.getIterationCount().intValue();
                byte[]  salt = defParams.getSalt();
                PBEParametersGenerator  generator = new PKCS5S2ParametersGenerator();

                generator.init(
                    PBEParametersGenerator.PKCS5PasswordToBytes(pFinder.getPassword()),
                    salt,
                    iterationCount);

                // TODO: read key size
                SecretKey key = new SecretKeySpec(((KeyParameter)generator.generateDerivedParameters(256)).getKey(), scheme.getObjectId().getId());

                Cipher cipher = Cipher.getInstance(scheme.getObjectId().getId(), provider);
                AlgorithmParameters algParams = AlgorithmParameters.getInstance(scheme.getObjectId().getId(), provider);

                algParams.init(scheme.getParameters().getDERObject().getEncoded());

                cipher.init(Cipher.DECRYPT_MODE, key, algParams);

                PrivateKeyInfo pInfo = PrivateKeyInfo.getInstance(ASN1Object.fromByteArray(cipher.doFinal(info.getEncryptedData())));
                PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pInfo.getEncoded());

                KeyFactory keyFact = KeyFactory.getInstance(pInfo.getAlgorithmId().getObjectId().getId(), provider);

                return keyFact.generatePrivate(keySpec);
            }
            catch (Exception e)
            {
                throw new PEMException("problem parsing ENCRYPTED PRIVATE KEY: " + e.toString(), e);   
            }
        }
    }
}
