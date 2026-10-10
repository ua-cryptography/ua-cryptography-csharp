import java.io.FileWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import org.bouncycastle.crypto.engines.DSTU7624Engine;
import org.bouncycastle.crypto.engines.DSTU7624WrapEngine;
import org.bouncycastle.crypto.macs.DSTU7624Mac;
import org.bouncycastle.crypto.macs.KGMac;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.CBCModeCipher;
import org.bouncycastle.crypto.modes.CFBBlockCipher;
import org.bouncycastle.crypto.modes.KCCMBlockCipher;
import org.bouncycastle.crypto.modes.KCTRBlockCipher;
import org.bouncycastle.crypto.modes.KGCMBlockCipher;
import org.bouncycastle.crypto.modes.KXTSBlockCipher;
import org.bouncycastle.crypto.modes.OFBBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.encoders.Hex;

/**
 * Generates reference vectors for every DSTU 7624 (Kalyna) mode with BouncyCastle Java (bcprov-jdk18on 1.86).
 * The C# translation in src/UA.Cryptography/Dstu7624 is tested against the output.
 *
 * <pre>
 * javac -cp bcprov-jdk18on-1.86.jar GenerateVectors.java
 * java -cp bcprov-jdk18on-1.86.jar:. GenerateVectors ../../tests/UA.Cryptography.Tests/TestData/vectors/dstu7624-bc-java-1.86.json
 * </pre>
 */
public class GenerateVectors
{
    private static final Random RANDOM = new Random(7624);
    private static final List<String> OUT = new ArrayList<>();

    private static final int[][] SIZES = { { 128, 128 }, { 128, 256 }, { 256, 256 }, { 256, 512 }, { 512, 512 } };

    public static void main(String[] args) throws Exception
    {
        for (int[] size : SIZES)
        {
            int block = size[0], keyBits = size[1], b = block / 8;
            byte[] key = random(keyBits / 8);

            // ECB, CBC
            byte[] data = random(3 * b);
            byte[] ecb = new byte[data.length];
            DSTU7624Engine engine = new DSTU7624Engine(block);
            engine.init(true, new KeyParameter(key));
            for (int i = 0; i < data.length; i += b)
            {
                engine.processBlock(data, i, ecb, i);
            }
            add("ecb", block, key, null, null, data, ecb, "");

            byte[] iv = random(b);
            CBCModeCipher cbc = CBCBlockCipher.newInstance(new DSTU7624Engine(block));
            cbc.init(true, new ParametersWithIV(new KeyParameter(key), iv));
            byte[] cbcOut = new byte[data.length];
            for (int i = 0; i < data.length; i += b)
            {
                cbc.processBlock(data, i, cbcOut, i);
            }
            add("cbc", block, key, iv, null, data, cbcOut, "");

            // CFB and OFB, full-block and 8-bit segments, with a partial last segment
            for (int segment : new int[] { block, 8 })
            {
                byte[] stream = random(3 * b + 5);
                iv = random(b);

                CFBBlockCipher cfb = new CFBBlockCipher(new DSTU7624Engine(block), segment);
                cfb.init(true, new ParametersWithIV(new KeyParameter(key), iv));
                byte[] cfbOut = new byte[stream.length];
                cfb.processBytes(stream, 0, stream.length, cfbOut, 0);
                add("cfb", block, key, iv, null, stream, cfbOut, "\"segment\":" + segment);

                OFBBlockCipher ofb = new OFBBlockCipher(new DSTU7624Engine(block), segment);
                ofb.init(true, new ParametersWithIV(new KeyParameter(key), iv));
                byte[] ofbOut = new byte[stream.length];
                ofb.processBytes(stream, 0, stream.length, ofbOut, 0);
                add("ofb", block, key, iv, null, stream, ofbOut, "\"segment\":" + segment);
            }

            // CTR: full and short IV, partial last block
            for (int ivLen : new int[] { b, b / 2 })
            {
                byte[] stream = random(3 * b + 7);
                iv = random(ivLen);
                KCTRBlockCipher ctr = new KCTRBlockCipher(new DSTU7624Engine(block));
                ctr.init(true, new ParametersWithIV(new KeyParameter(key), iv));
                byte[] ctrOut = new byte[stream.length];
                ctr.processBytes(stream, 0, stream.length, ctrOut, 0);
                add("ctr", block, key, iv, null, stream, ctrOut, "");
            }

            // MAC
            for (int q : new int[] { block, 64 })
            {
                for (int blocks : new int[] { 1, 3 })
                {
                    byte[] message = random(blocks * b);
                    DSTU7624Mac mac = new DSTU7624Mac(block, q);
                    mac.init(new KeyParameter(key));
                    mac.update(message, 0, message.length);
                    byte[] tag = new byte[q / 8];
                    mac.doFinal(tag, 0);
                    add("cmac", block, key, null, null, message, tag, "\"macBits\":" + q);
                }
            }

            // Key wrap
            for (int blocks : new int[] { 1, 3 })
            {
                byte[] wrapKey = random(blocks * b);
                DSTU7624WrapEngine wrap = new DSTU7624WrapEngine(block);
                wrap.init(true, new KeyParameter(key));
                add("kw", block, key, null, null, wrapKey, wrap.wrap(wrapKey, 0, wrapKey.length), "");
            }

            // CCM
            for (int nb : new int[] { 4, 6, 8 })
            {
                for (int macBits : new int[] { 64, 128, block })
                {
                    if (macBits > block)
                    {
                        continue;
                    }
                    for (int aadLen : new int[] { 0, 3, 2 * b + b / 2 })
                    {
                        for (int dataLen : new int[] { 0, b, 2 * b + 3 })
                        {
                            byte[] nonce = random(nb == 6 ? 5 : b);
                            byte[] aad = random(aadLen);
                            byte[] pt = random(dataLen);
                            KCCMBlockCipher ccm = new KCCMBlockCipher(new DSTU7624Engine(block), nb);
                            ccm.init(true, new AEADParameters(new KeyParameter(key), macBits, nonce, aad));
                            byte[] out = new byte[ccm.getOutputSize(pt.length)];
                            int len = ccm.processBytes(pt, 0, pt.length, out, 0);
                            ccm.doFinal(out, len);
                            add("ccm", block, key, nonce, aad, pt, out, "\"nb\":" + nb + ",\"macBits\":" + macBits);
                        }
                    }
                }
            }
            {
                // a message longer than 255 blocks: the gamma counter must carry into its second byte
                byte[] nonce = random(b), aad = random(5), pt = random(300 * b + 1);
                KCCMBlockCipher ccm = new KCCMBlockCipher(new DSTU7624Engine(block), 4);
                ccm.init(true, new AEADParameters(new KeyParameter(key), 64, nonce, aad));
                byte[] out = new byte[ccm.getOutputSize(pt.length)];
                int len = ccm.processBytes(pt, 0, pt.length, out, 0);
                ccm.doFinal(out, len);
                add("ccm", block, key, nonce, aad, pt, out, "\"nb\":4,\"macBits\":64");
            }

            // GCM
            for (int macBits : new int[] { 64, block })
            {
                for (int aadLen : new int[] { 0, b + b / 2 })
                {
                    for (int dataLen : new int[] { 0, 2 * b + 5 })
                    {
                        for (int nonceLen : new int[] { b, 12 })
                        {
                            byte[] nonce = random(nonceLen), aad = random(aadLen), pt = random(dataLen);
                            KGCMBlockCipher gcm = new KGCMBlockCipher(new DSTU7624Engine(block));
                            gcm.init(true, new AEADParameters(new KeyParameter(key), macBits, nonce, aad));
                            byte[] out = new byte[gcm.getOutputSize(pt.length)];
                            int len = gcm.processBytes(pt, 0, pt.length, out, 0);
                            gcm.doFinal(out, len);
                            add("gcm", block, key, nonce, aad, pt, out, "\"macBits\":" + macBits);
                        }
                    }
                }
            }

            // GMAC
            for (int dataLen : new int[] { b, 2 * b + 5 })
            {
                for (int macBits : new int[] { 64, block })
                {
                    byte[] nonce = random(b), message = random(dataLen);
                    KGMac gmac = new KGMac(new KGCMBlockCipher(new DSTU7624Engine(block)), macBits);
                    gmac.init(new ParametersWithIV(new KeyParameter(key), nonce));
                    gmac.update(message, 0, message.length);
                    byte[] tag = new byte[macBits / 8];
                    gmac.doFinal(tag, 0);
                    add("gmac", block, key, nonce, null, message, tag, "\"macBits\":" + macBits);
                }
            }

            // XTS
            for (int blocks : new int[] { 1, 3 })
            {
                byte[] xtsData = random(blocks * b);
                iv = random(b);
                KXTSBlockCipher xts = new KXTSBlockCipher(new DSTU7624Engine(block));
                xts.init(true, new ParametersWithIV(new KeyParameter(key), iv));
                byte[] xtsOut = new byte[xtsData.length];
                xts.processBytes(xtsData, 0, xtsData.length, xtsOut, 0);
                add("xts", block, key, iv, null, xtsData, xtsOut, "");
            }
        }

        try (FileWriter w = new FileWriter(args[0]))
        {
            w.write("[\n" + String.join(",\n", OUT) + "\n]\n");
        }
        System.out.println(OUT.size() + " vectors written to " + args[0]);
    }

    private static byte[] random(int length)
    {
        byte[] b = new byte[length];
        RANDOM.nextBytes(b);
        return b;
    }

    private static void add(String mode, int block, byte[] key, byte[] iv, byte[] aad, byte[] input, byte[] output, String extra)
    {
        OUT.add("{\"mode\":\"" + mode + "\",\"block\":" + block
            + ",\"key\":\"" + Hex.toHexString(key) + "\""
            + ",\"iv\":\"" + (iv == null ? "" : Hex.toHexString(iv)) + "\""
            + ",\"aad\":\"" + (aad == null ? "" : Hex.toHexString(aad)) + "\""
            + ",\"input\":\"" + Hex.toHexString(input) + "\""
            + ",\"output\":\"" + Hex.toHexString(output) + "\""
            + (extra.isEmpty() ? "" : "," + extra) + "}");
    }
}
