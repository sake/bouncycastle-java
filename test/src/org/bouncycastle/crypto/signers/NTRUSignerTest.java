/**
 * Copyright (c) 2011 Tim Buktu (tbuktu@hotmail.com)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

package org.bouncycastle.crypto.signers;


import java.io.IOException;
import java.util.Random;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.NTRUSigningKeyPairGenerator;
import org.bouncycastle.crypto.params.NTRUSigningKeyGenerationParameters;
import org.bouncycastle.crypto.params.NTRUSigningPrivateKeyParameters;
import org.bouncycastle.crypto.params.NTRUSigningPublicKeyParameters;
import org.bouncycastle.math.ntru.polynomial.IntegerPolynomial;
import org.bouncycastle.math.ntru.polynomial.Polynomial;
import org.bouncycastle.util.Arrays;

public class NTRUSignerTest
    extends TestCase
{
    public void testCreateBasis()
    {
        for (NTRUSigningKeyGenerationParameters params : new NTRUSigningKeyGenerationParameters[]{NTRUSigningKeyGenerationParameters.TEST157.clone(), NTRUSigningKeyGenerationParameters.TEST157_PROD.clone()})
        {
            testCreateBasis(params);
        }
    }

    private void testCreateBasis(NTRUSigningKeyGenerationParameters params)
    {
        NTRUSigningKeyPairGenerator ntru = new NTRUSigningKeyPairGenerator();

        ntru.init(params);

        NTRUSigningKeyPairGenerator.FGBasis basis = (NTRUSigningKeyPairGenerator.FGBasis)ntru.generateBoundedBasis();
        assertTrue(equalsQ(basis.f, basis.fPrime, basis.F, basis.G, params.q, params.N));

        // test KeyGenAlg.FLOAT (default=RESULTANT)
        params.keyGenAlg = NTRUSigningKeyGenerationParameters.KEY_GEN_ALG_FLOAT;
        ntru.init(params);
        basis = (NTRUSigningKeyPairGenerator.FGBasis)ntru.generateBoundedBasis();
        assertTrue(equalsQ(basis.f, basis.fPrime, basis.F, basis.G, params.q, params.N));
    }

    // verifies that f*G-g*F=q
    private boolean equalsQ(Polynomial f, Polynomial g, IntegerPolynomial F, IntegerPolynomial G, int q, int N)
    {
        IntegerPolynomial x = f.mult(G);
        x.sub(g.mult(F));
        boolean equalsQ = true;
        for (int i = 1; i < x.coeffs.length; i++)
        {
            equalsQ &= x.coeffs[i] == 0;
        }
        equalsQ &= x.coeffs[0] == q;
        return equalsQ;
    }

    /**
     * a test for the one-method-call variants: sign(byte, SignatureKeyPair) and verify(byte[], byte[], SignatureKeyPair)
     */
    public void testSignVerify()
        throws IOException
    {
        for (NTRUSigningKeyGenerationParameters params : new NTRUSigningKeyGenerationParameters[]{NTRUSigningKeyGenerationParameters.TEST157.clone(), NTRUSigningKeyGenerationParameters.TEST157_PROD.clone()})
        {
            testSignVerify(params);
        }
    }

    private void testSignVerify(NTRUSigningKeyGenerationParameters params)
        throws IOException
    {
        NTRUSigner ntru = new NTRUSigner(params.getSigningParameters());
        NTRUSigningKeyPairGenerator kGen = new NTRUSigningKeyPairGenerator();

        kGen.init(params);

        AsymmetricCipherKeyPair kp = kGen.generateKeyPair();

        Random rng = new Random();
        byte[] msg = new byte[10 + rng.nextInt(1000)];
        rng.nextBytes(msg);

        // sign and verify
        ntru.init(true, kp.getPrivate());

        ntru.update(msg, 0, msg.length);

        byte[] s = ntru.generateSignature();

        ntru.init(false, kp.getPublic());

        ntru.update(msg, 0, msg.length);

        boolean valid = ntru.verifySignature(s);

        assertTrue(valid);

        // altering the signature should make it invalid
        s[rng.nextInt(params.N)] += 1;
        ntru.init(false, kp.getPublic());

        ntru.update(msg, 0, msg.length);

        valid = ntru.verifySignature(s);
        assertFalse(valid);

        // test that a random signature fails
        rng.nextBytes(s);

        ntru.init(false, kp.getPublic());

        ntru.update(msg, 0, msg.length);

        valid = ntru.verifySignature(s);
        assertFalse(valid);

        // encode, decode keypair, test
        NTRUSigningPrivateKeyParameters priv = new NTRUSigningPrivateKeyParameters(((NTRUSigningPrivateKeyParameters)kp.getPrivate()).getEncoded(), params);
        NTRUSigningPublicKeyParameters pub = new NTRUSigningPublicKeyParameters(((NTRUSigningPublicKeyParameters)kp.getPublic()).getEncoded(), params.getSigningParameters());
        kp = new AsymmetricCipherKeyPair(pub, priv);

        ntru.init(true, kp.getPrivate());
        ntru.update(msg, 0, msg.length);

        s = ntru.generateSignature();

        ntru.init(false, kp.getPublic());
        ntru.update(msg, 0, msg.length);

        valid = ntru.verifySignature(s);
        assertTrue(valid);

        // altering the signature should make it invalid
        s[rng.nextInt(s.length)] += 1;
        ntru.init(false, kp.getPublic());
        ntru.update(msg, 0, msg.length);
        valid = ntru.verifySignature(s);
        assertFalse(valid);

        // sparse/dense
        params.sparse = !params.sparse;

        ntru.init(true, kp.getPrivate());
        ntru.update(msg, 0, msg.length);

        s = ntru.generateSignature();

        ntru.init(false, kp.getPublic());
        ntru.update(msg, 0, msg.length);
        valid = ntru.verifySignature(s);
        assertTrue(valid);

        s[rng.nextInt(s.length)] += 1;
        ntru.init(false, kp.getPublic());
        ntru.update(msg, 0, msg.length);
        valid = ntru.verifySignature(s);
        assertFalse(valid);
        params.sparse = !params.sparse;

        // decrease NormBound to force multiple signing attempts
        NTRUSigningKeyGenerationParameters params2 = params.clone();
        params2.normBoundSq *= 4.0 / 9;
        params2.signFailTolerance = 10000;
        ntru = new NTRUSigner(params2.getSigningParameters());

        ntru.init(true, kp.getPrivate());
        ntru.update(msg, 0, msg.length);

        s = ntru.generateSignature();

        ntru.init(false, kp.getPublic());
        ntru.update(msg, 0, msg.length);
        valid = ntru.verifySignature(s);

        assertTrue(valid);

        // test KeyGenAlg.FLOAT (default=RESULTANT)
        params2 = params.clone();
        params.keyGenAlg = NTRUSigningKeyGenerationParameters.KEY_GEN_ALG_FLOAT;
        ntru = new NTRUSigner(params.getSigningParameters());

        kGen.init(params);

        kp = kGen.generateKeyPair();
        ntru.init(true, kp.getPrivate());
        ntru.update(msg, 0, msg.length);

        s = ntru.generateSignature();
        ntru.init(false, kp.getPublic());
        ntru.update(msg, 0, msg.length);
        valid = ntru.verifySignature(s);
        assertTrue(valid);
        s[rng.nextInt(s.length)] += 1;
        ntru.init(false, kp.getPublic());
        ntru.update(msg, 0, msg.length);
        valid = ntru.verifySignature(s);
        assertFalse(valid);
    }

    /**
     * test for the initSign/update/sign and initVerify/update/verify variant
     */
    public void testInitUpdateSign()
    {
        for (NTRUSigningKeyGenerationParameters params : new NTRUSigningKeyGenerationParameters[]{NTRUSigningKeyGenerationParameters.TEST157.clone(), NTRUSigningKeyGenerationParameters.TEST157_PROD.clone()})
        {
            testInitUpdateSign(params);
        }
    }

    private void testInitUpdateSign(NTRUSigningKeyGenerationParameters params)
    {
        NTRUSigner ntru = new NTRUSigner(params.getSigningParameters());
        NTRUSigningKeyPairGenerator kGen = new NTRUSigningKeyPairGenerator();

        kGen.init(params);

        AsymmetricCipherKeyPair kp = kGen.generateKeyPair();

        Random rng = new Random();
        byte[] msg = new byte[10 + rng.nextInt(1000)];
        rng.nextBytes(msg);

        // sign and verify a message in two pieces each
        ntru.init(true, kp.getPrivate());
        int splitIdx = rng.nextInt(msg.length);
        ntru.update(msg[0]);   // first byte
        ntru.update(msg, 1, splitIdx - 1);   // part 1 of msg
        ntru.update(msg, splitIdx, msg.length - splitIdx);
        byte[] s = ntru.generateSignature();   // part 2 of msg
        ntru.init(false, kp.getPublic());
        splitIdx = rng.nextInt(msg.length);
        ntru.update(msg, 0, splitIdx);   // part 1 of msg
        ntru.update(msg, splitIdx, msg.length - splitIdx);   // part 2 of msg
        boolean valid = ntru.verifySignature(s);
        assertTrue(valid);
        // verify the same signature with the one-step method
        ntru.init(false, (NTRUSigningPublicKeyParameters)kp.getPublic());
        ntru.update(msg, 0, msg.length);   // part 1 of msg
        valid = ntru.verifySignature(s);
        assertTrue(valid);

        // sign using the one-step method and verify using the multi-step method
        ntru.init(true, kp.getPrivate());
        ntru.update(msg, 0, msg.length);
        s = ntru.generateSignature();
        ntru.init(false, (NTRUSigningPublicKeyParameters)kp.getPublic());
        splitIdx = rng.nextInt(msg.length);
        ntru.update(msg, 0, splitIdx);   // part 1 of msg
        ntru.update(msg, splitIdx, msg.length - splitIdx);   // part 2 of msg
        valid = ntru.verifySignature(s);
        assertTrue(valid);
    }

    public void testCreateMsgRep()
    {
        for (NTRUSigningKeyGenerationParameters params : new NTRUSigningKeyGenerationParameters[]{NTRUSigningKeyGenerationParameters.TEST157.clone(), NTRUSigningKeyGenerationParameters.TEST157_PROD.clone()})
        {
            testCreateMsgRep(params);
        }
    }

    private void testCreateMsgRep(NTRUSigningKeyGenerationParameters params)
    {
        NTRUSigner ntru = new NTRUSigner(params.getSigningParameters());
        byte[] msgHash = "adfsadfsdfs23234234".getBytes();

        // verify that the message representative is reproducible
        IntegerPolynomial i1 = ntru.createMsgRep(msgHash, 1);
        IntegerPolynomial i2 = ntru.createMsgRep(msgHash, 1);
        assertTrue(Arrays.areEqual(i1.coeffs, i2.coeffs));
        i1 = ntru.createMsgRep(msgHash, 5);
        i2 = ntru.createMsgRep(msgHash, 5);
        assertTrue(Arrays.areEqual(i1.coeffs, i2.coeffs));

        i1 = ntru.createMsgRep(msgHash, 2);
        i2 = ntru.createMsgRep(msgHash, 3);
        assertFalse(Arrays.areEqual(i1.coeffs, i2.coeffs));
    }
}