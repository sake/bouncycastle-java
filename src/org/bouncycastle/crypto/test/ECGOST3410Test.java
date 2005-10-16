package org.bouncycastle.crypto.test;

import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.signers.ECGOST3410Signer;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.GOST3411Digest;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 *  ECGOST3410 tests are taken from GOST R 34.10-2001.
 */
public class ECGOST3410Test
        implements Test
 {
    byte[] hashmessage = Hex.decode("3042453136414534424341374533364339313734453431443642453241453435");
    
     /**
     * ECGOST3410 over the field Fp<br>
     */
    private class ECGOST3410_TEST
        implements Test
    {
        BigInteger r = new BigInteger("29700980915817952874371204983938256990422752107994319651632687982059210933395");
        BigInteger s = new BigInteger("574973400270084654178925310019147038455227042649098563933718999175515839552");

        SecureRandom    k = new SecureRandom()
        {
            public void nextBytes(byte[] bytes)
            {
                byte[] k = new BigInteger("53854137677348463731403841147996619241504003434302020712960838528893196233395").toByteArray();

                System.arraycopy(k, k.length-bytes.length, bytes, 0, bytes.length);
            }
        };

        public String getName()
        {
            return "ECGOST3410 - TEST";
        }

        public TestResult perform()
        {
            BigInteger mod_p = new BigInteger("57896044618658097711785492504343953926634992332820282019728792003956564821041"); //p

            ECCurve.Fp curve = new ECCurve.Fp(
                mod_p, // p
                new BigInteger("7"), // a
                new BigInteger("43308876546767276905765904595650931995942111794451039583252968842033849580414")); // b

            ECDomainParameters params = new ECDomainParameters(
                curve,
                new ECPoint.Fp(curve,
                               new ECFieldElement.Fp(mod_p,new BigInteger("2")), // x
                               new ECFieldElement.Fp(mod_p,new BigInteger("4018974056539037503335449422937059775635739389905545080690979365213431566280"))), // y
                new BigInteger("57896044618658097711785492504343953927082934583725450622380973592137631069619")); // q

            ECPrivateKeyParameters priKey = new ECPrivateKeyParameters(
                new BigInteger("55441196065363246126355624130324183196576709222340016572108097750006097525544"), // d
                params);

            ParametersWithRandom param = new ParametersWithRandom(priKey, k);

            ECGOST3410Signer ecgost3410 = new ECGOST3410Signer();

            ecgost3410.init(true, param);

            byte[] mVal = new BigInteger("20798893674476452017134061561508270130637142515379653289952617252661468872421").toByteArray();
            byte[] message = new byte[mVal.length];
            
            for (int i = 0; i != mVal.length; i++)
            {
                message[i] = mVal[mVal.length - 1 - i];
            }
            
            BigInteger[] sig = ecgost3410.generateSignature(message);

            if (!r.equals(sig[0]))
            {
                return new SimpleTestResult(false, getName()
                    + ": r component wrong." + System.getProperty("line.separator")
                    + " expecting: " + r + System.getProperty("line.separator")
                    + " got      : " + sig[0]);
            }

            if (!s.equals(sig[1]))
            {
                return new SimpleTestResult(false, getName()
                    + ": s component wrong." + System.getProperty("line.separator")
                    + " expecting: " + s + System.getProperty("line.separator")
                    + " got      : " + sig[1]);
            }

            // Verify the signature
            ECPublicKeyParameters pubKey = new ECPublicKeyParameters(
                new ECPoint.Fp(curve,
                               new ECFieldElement.Fp(mod_p, new BigInteger("57520216126176808443631405023338071176630104906313632182896741342206604859403")), // x
                               new ECFieldElement.Fp(mod_p, new BigInteger("17614944419213781543809391949654080031942662045363639260709847859438286763994"))), // y
                params);

            ecgost3410.init(false, pubKey);
            if (ecgost3410.verifySignature(message, sig[0], sig[1]))
            {
                return new SimpleTestResult(true, getName() + ": Okay");
            }
            else
            {
                return new SimpleTestResult(false, getName() + ": verification fails");
            }
        }
    }

    /**
     * Test Sign & Verify with test parameters
     * see: http://www.ietf.org/internet-drafts/draft-popov-cryptopro-cpalgs-01.txt
     * gostR3410-2001-TestParamSet  P.46
     */
    private class ECGOST3410_TestParam
        implements Test
    {
        public String getName()
        {
            return "ECGOST3410 with test parameters.";
        }

        public TestResult perform()
        {
            SecureRandom    random = new SecureRandom();

            BigInteger mod_p = new BigInteger("57896044618658097711785492504343953926634992332820282019728792003956564821041"); //p

            ECCurve.Fp curve = new ECCurve.Fp(
                mod_p, // p
                new BigInteger("7"), // a
                new BigInteger("43308876546767276905765904595650931995942111794451039583252968842033849580414")); // b

            ECDomainParameters params = new ECDomainParameters(
                curve,
                new ECPoint.Fp(curve,
                               new ECFieldElement.Fp(mod_p,new BigInteger("2")), // x
                               new ECFieldElement.Fp(mod_p,new BigInteger("4018974056539037503335449422937059775635739389905545080690979365213431566280"))), // y
                new BigInteger("57896044618658097711785492504343953927082934583725450622380973592137631069619")); // q

            ECKeyPairGenerator          pGen = new ECKeyPairGenerator();
            ECKeyGenerationParameters   genParam = new ECKeyGenerationParameters(
                                            params,
                                            random);

            pGen.init(genParam);

            AsymmetricCipherKeyPair  pair = pGen.generateKeyPair();

            ParametersWithRandom param = new ParametersWithRandom(pair.getPrivate(), random);

            ECGOST3410Signer ecgost3410 = new ECGOST3410Signer();

            ecgost3410.init(true, param);

            //get hash message using the digest GOST3411.
            byte[] message = "Message for sign".getBytes();
            GOST3411Digest  gost3411 = new GOST3411Digest();
            gost3411.update(message, 0, message.length);
            byte[] hashmessage = new byte[gost3411.getDigestSize()];
            gost3411.doFinal(hashmessage, 0);

            BigInteger[] sig = ecgost3410.generateSignature(hashmessage);

            ecgost3410.init(false, pair.getPublic());

            if (ecgost3410.verifySignature(hashmessage, sig[0], sig[1]))
            {
                return new SimpleTestResult(true, getName() + ": Okay");
            }
            else
            {
                return new SimpleTestResult(false, getName() + ": signature fails");
            }
        }
    }

    /**
     * Test Sign & Verify with A parameters
     * see: http://www.ietf.org/internet-drafts/draft-popov-cryptopro-cpalgs-01.txt
     * gostR3410-2001-CryptoPro-A-ParamSet  P.47
     */
    private class ECGOST3410_AParam
        implements Test
    {
        public String getName()
        {
            return "ECGOST3410 with  CryptoPro-A parameters.";
        }

        public TestResult perform()
        {
            SecureRandom    random = new SecureRandom();

            BigInteger mod_p = new BigInteger("115792089237316195423570985008687907853269984665640564039457584007913129639319"); //p

            ECCurve.Fp curve = new ECCurve.Fp(
                mod_p, // p
                new BigInteger("115792089237316195423570985008687907853269984665640564039457584007913129639316"), // a
                new BigInteger("166")); // b

            ECDomainParameters params = new ECDomainParameters(
                curve,
                new ECPoint.Fp(curve,
                               new ECFieldElement.Fp(mod_p,new BigInteger("1")), // x
                               new ECFieldElement.Fp(mod_p,new BigInteger("64033881142927202683649881450433473985931760268884941288852745803908878638612"))), // y
                new BigInteger("115792089237316195423570985008687907853073762908499243225378155805079068850323")); // q

            ECKeyPairGenerator          pGen = new ECKeyPairGenerator();
            ECKeyGenerationParameters   genParam = new ECKeyGenerationParameters(
                                            params,
                                            random);

            pGen.init(genParam);

            AsymmetricCipherKeyPair  pair = pGen.generateKeyPair();

            ParametersWithRandom param = new ParametersWithRandom(pair.getPrivate(), random);

            ECGOST3410Signer ecgost3410 = new ECGOST3410Signer();

            ecgost3410.init(true, param);

            BigInteger[] sig = ecgost3410.generateSignature(hashmessage);

            ecgost3410.init(false, pair.getPublic());

            if (ecgost3410.verifySignature(hashmessage, sig[0], sig[1]))
            {
                return new SimpleTestResult(true, getName() + ": Okay");
            }
            else
            {
                return new SimpleTestResult(false, getName() + ": signature fails");
            }
        }
    }

    /**
     * Test Sign & Verify with B parameters
     * see: http://www.ietf.org/internet-drafts/draft-popov-cryptopro-cpalgs-01.txt
     * gostR3410-2001-CryptoPro-B-ParamSet  P.47-48
     */
    private class ECGOST3410_BParam
        implements Test
    {
        public String getName()
        {
            return "ECGOST3410 with  CryptoPro-B parameters.";
        }

        public TestResult perform()
        {
            SecureRandom    random = new SecureRandom();

            BigInteger mod_p = new BigInteger("57896044618658097711785492504343953926634992332820282019728792003956564823193"); //p

            ECCurve.Fp curve = new ECCurve.Fp(
                mod_p, // p
                new BigInteger("57896044618658097711785492504343953926634992332820282019728792003956564823190"), // a
                new BigInteger("28091019353058090096996979000309560759124368558014865957655842872397301267595")); // b

            ECDomainParameters params = new ECDomainParameters(
                curve,
                new ECPoint.Fp(curve,
                               new ECFieldElement.Fp(mod_p,new BigInteger("1")), // x
                               new ECFieldElement.Fp(mod_p,new BigInteger("28792665814854611296992347458380284135028636778229113005756334730996303888124"))), // y
                new BigInteger("57896044618658097711785492504343953927102133160255826820068844496087732066703")); // q

            ECKeyPairGenerator          pGen = new ECKeyPairGenerator();
            ECKeyGenerationParameters   genParam = new ECKeyGenerationParameters(
                                            params,
                                            random);

            pGen.init(genParam);

            AsymmetricCipherKeyPair  pair = pGen.generateKeyPair();

            ParametersWithRandom param = new ParametersWithRandom(pair.getPrivate(), random);

            ECGOST3410Signer ecgost3410 = new ECGOST3410Signer();

            ecgost3410.init(true, param);

            BigInteger[] sig = ecgost3410.generateSignature(hashmessage);

            ecgost3410.init(false, pair.getPublic());

            if (ecgost3410.verifySignature(hashmessage, sig[0], sig[1]))
            {
                return new SimpleTestResult(true, getName() + ": Okay");
            }
            else
            {
                return new SimpleTestResult(false, getName() + ": signature fails");
            }
        }
    }

    /**
     * Test Sign & Verify with C parameters
     * see: http://www.ietf.org/internet-drafts/draft-popov-cryptopro-cpalgs-01.txt
     * gostR3410-2001-CryptoPro-C-ParamSet  P.48
     */
    private class ECGOST3410_CParam
        implements Test
    {
        public String getName()
        {
            return "ECGOST3410 with  CryptoPro-C parameters.";
        }

        public TestResult perform()
        {
            SecureRandom    random = new SecureRandom();

            BigInteger mod_p = new BigInteger("70390085352083305199547718019018437841079516630045180471284346843705633502619"); //p

            ECCurve.Fp curve = new ECCurve.Fp(
                mod_p, // p
                new BigInteger("70390085352083305199547718019018437841079516630045180471284346843705633502616"), // a
                new BigInteger("32858")); // b

            ECDomainParameters params = new ECDomainParameters(
                curve,
                new ECPoint.Fp(curve,
                               new ECFieldElement.Fp(mod_p,new BigInteger("0")), // x
                               new ECFieldElement.Fp(mod_p,new BigInteger("29818893917731240733471273240314769927240550812383695689146495261604565990247"))), // y
                new BigInteger("70390085352083305199547718019018437840920882647164081035322601458352298396601")); // q

            ECKeyPairGenerator          pGen = new ECKeyPairGenerator();
            ECKeyGenerationParameters   genParam = new ECKeyGenerationParameters(
                                            params,
                                            random);

            pGen.init(genParam);

            AsymmetricCipherKeyPair  pair = pGen.generateKeyPair();

            ParametersWithRandom param = new ParametersWithRandom(pair.getPrivate(), random);

            ECGOST3410Signer ecgost3410 = new ECGOST3410Signer();

            ecgost3410.init(true, param);

            BigInteger[] sig = ecgost3410.generateSignature(hashmessage);

            ecgost3410.init(false, pair.getPublic());

            if (ecgost3410.verifySignature(hashmessage, sig[0], sig[1]))
            {
                return new SimpleTestResult(true, getName() + ": Okay");
            }
            else
            {
                return new SimpleTestResult(false, getName() + ": signature fails");
            }
        }
    }

    Test tests[] =
    {
        new ECGOST3410_TEST(),
        new ECGOST3410_TestParam(),
        new ECGOST3410_AParam(),
        new ECGOST3410_BParam(),
        new ECGOST3410_CParam()
    };

    public String getName()
    {
        return "ECGOST3410";
    }

    public TestResult perform()
    {
        for (int i = 0; i != tests.length; i++)
        {
            TestResult  result = tests[i].perform();

            if (!result.isSuccessful())
            {
                return result;
            }
        }

        return new SimpleTestResult(true, "ECGOST3410: Okay");
    }

    public static void main(
        String[]    args)
    {
        ECGOST3410Test  test = new ECGOST3410Test();
        TestResult      result = test.perform();

        System.out.println(result);
    }
}
