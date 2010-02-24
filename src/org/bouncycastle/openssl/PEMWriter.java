package org.bouncycastle.openssl;

import java.io.IOException;
import java.io.Writer;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.LinkedHashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPrivateKeyStructure;
import org.bouncycastle.asn1.x509.DSAParameter;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.bouncycastle.x509.X509AttributeCertificate;
import org.bouncycastle.x509.X509V2AttributeCertificate;

/**
 * General purpose writer for OpenSSL PEM objects.
 */
public class PEMWriter
    extends PemWriter
{
    private String provider;

    /**
     * Base constructor.
     * 
     * @param out output stream to use.
     */
    public PEMWriter(Writer out)
    {
        this(out, "BC");
    }

    public PEMWriter(
        Writer  out,
        String  provider)
    {
        super(out);

        this.provider = provider;
    }

    private String getHexEncoded(byte[] bytes)
        throws IOException
    {
        bytes = Hex.encode(bytes);

        char[] chars = new char[bytes.length];

        for (int i = 0; i != bytes.length; i++)
        {
            chars[i] = (char)bytes[i];
        }

        return new String(chars);
    }

    public void writeObject(
        Object  o) 
        throws IOException
    {
        String  type;
        byte[]  encoding;
        
        if (o instanceof X509Certificate)
        {
            type = "CERTIFICATE";
            try
            {
                encoding = ((X509Certificate)o).getEncoded();
            }
            catch (CertificateEncodingException e)
            {
                throw new IOException("Cannot encode object: " + e.toString());
            }
        }
        else if (o instanceof X509CRL)
        {
            type = "X509 CRL";
            try
            {
                encoding = ((X509CRL)o).getEncoded();
            }
            catch (CRLException e)
            {
                throw new IOException("Cannot encode object: " + e.toString());
            }
        }
        else if (o instanceof KeyPair)
        {
            writeObject(((KeyPair)o).getPrivate());
            return;
        }
        else if (o instanceof PrivateKey)
        {
            PrivateKeyInfo info = new PrivateKeyInfo(
                (ASN1Sequence) ASN1Object.fromByteArray(((Key)o).getEncoded()));

            if (o instanceof RSAPrivateKey)
            {
                type = "RSA PRIVATE KEY";

                encoding = info.getPrivateKey().getEncoded();
            }
            else if (o instanceof DSAPrivateKey)
            {
                type = "DSA PRIVATE KEY";
                
                DSAParameter        p = DSAParameter.getInstance(info.getAlgorithmId().getParameters());
                ASN1EncodableVector v = new ASN1EncodableVector();
                
                v.add(new DERInteger(0));
                v.add(new DERInteger(p.getP()));
                v.add(new DERInteger(p.getQ()));
                v.add(new DERInteger(p.getG()));
                
                BigInteger x = ((DSAPrivateKey)o).getX();
                BigInteger y = p.getG().modPow(x, p.getP());
                
                v.add(new DERInteger(y));
                v.add(new DERInteger(x));

                encoding = new DERSequence(v).getEncoded();
            }
            else if (((PrivateKey)o).getAlgorithm().equals("ECDSA"))
            {
                type = "EC PRIVATE KEY";

                encoding = info.getPrivateKey().getEncoded();
            }
            else
            {
                throw new IOException("Cannot identify private key");
            }
        }
        else if (o instanceof PublicKey)
        {
            type = "PUBLIC KEY";
            
            encoding = ((PublicKey)o).getEncoded();
        }
        else if (o instanceof X509AttributeCertificate)
        {
            type = "ATTRIBUTE CERTIFICATE";
            encoding = ((X509V2AttributeCertificate)o).getEncoded();
        }
        else if (o instanceof PKCS10CertificationRequest)
        {
            type = "CERTIFICATE REQUEST";
            encoding = ((PKCS10CertificationRequest)o).getEncoded();
        }
        else if (o instanceof ContentInfo)
        {
            type = "PKCS7";
            encoding = ((ContentInfo)o).getEncoded();
        }
        else
        {
            throw new IOException("unknown object passed - can't encode.");
        }

        writePemObject(new PemObject(type, encoding));
    }

    public void writeObject(
        Object       obj,
        String       algorithm,
        char[]       password,
        SecureRandom random)
        throws IOException
    {
        if (obj instanceof KeyPair)
        {
            writeObject(((KeyPair)obj).getPrivate());
            return;
        }

        String type = null;
        byte[] keyData = null;

        if (obj instanceof RSAPrivateCrtKey)
        {
            type = "RSA PRIVATE KEY";

            RSAPrivateCrtKey k = (RSAPrivateCrtKey)obj;

            RSAPrivateKeyStructure keyStruct = new RSAPrivateKeyStructure(
                k.getModulus(),
                k.getPublicExponent(),
                k.getPrivateExponent(),
                k.getPrimeP(),
                k.getPrimeQ(),
                k.getPrimeExponentP(),
                k.getPrimeExponentQ(),
                k.getCrtCoefficient());

            // convert to bytearray
            keyData = keyStruct.getEncoded();
        }
        else if (obj instanceof DSAPrivateKey)
        {
            type = "DSA PRIVATE KEY";

            DSAPrivateKey       k = (DSAPrivateKey)obj;
            DSAParams           p = k.getParams();
            ASN1EncodableVector v = new ASN1EncodableVector();

            v.add(new DERInteger(0));
            v.add(new DERInteger(p.getP()));
            v.add(new DERInteger(p.getQ()));
            v.add(new DERInteger(p.getG()));

            BigInteger x = k.getX();
            BigInteger y = p.getG().modPow(x, p.getP());

            v.add(new DERInteger(y));
            v.add(new DERInteger(x));

            keyData = new DERSequence(v).getEncoded();
        }
        else if (obj instanceof PrivateKey && "ECDSA".equals(((PrivateKey)obj).getAlgorithm()))
        {
            type = "EC PRIVATE KEY";

            PrivateKeyInfo      privInfo = PrivateKeyInfo.getInstance(ASN1Object.fromByteArray(((PrivateKey)obj).getEncoded()));

            keyData = privInfo.getPrivateKey().getEncoded();
        }

        if (type == null || keyData == null)
        {
            // TODO Support other types?
            throw new IllegalArgumentException("Object type not supported: " + obj.getClass().getName());
        }


        String dekAlgName = Strings.toUpperCase(algorithm);

        // Note: For backward compatibility
        if (dekAlgName.equals("DESEDE"))
        {
            dekAlgName = "DES-EDE3-CBC";
        }

        int ivLength = dekAlgName.startsWith("AES-") ? 16 : 8;

        byte[] iv = new byte[ivLength];
        random.nextBytes(iv);

        byte[] encData = PEMUtilities.crypt(true, provider, keyData, password, dekAlgName, iv);

        Map headers = new LinkedHashMap();

        headers.put("Proc-Type", "4,ENCRYPTED");
        headers.put("DEK-Info", dekAlgName + "," + getHexEncoded(iv));

        writePemObject(new PemObject(type, headers, encData));
    }
}
