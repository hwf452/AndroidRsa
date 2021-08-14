package com.rehome.rsa;

/**
 * @ Author  : huangwenfei
 * @ Date    : Created in 2021/8/11 10:44 下午
 * @ Version : $1.0.0.0
 * @ Description: RSA分段加密，加密内容无限制，无论内容多长，都可以加密。
 */


import android.util.Base64;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.Cipher;

public class RSAAndroid {
    private static String TAG = "RSAAndroid";
    public static final String RSA = "RSA";// 非对称加密密钥算法
    /**加密方式，android的*/
    // public static final String ECB_PKCS1_PADDING = "RSA/None/NoPadding";
    /**加密方式，标准jdk的*/
    //public static final String ECB_PKCS1_PADDING = "RSA/None/PKCS1Padding";
    public static final String ECB_PKCS1_PADDING = "RSA/ECB/PKCS1Padding";
    public static final int DEFAULT_KEY_SIZE = 2048;//秘钥默认长度
    public static final byte[] DEFAULT_SPLIT = "#PART#".getBytes();    // 当要加密的内容超过bufferSize，则采用partSplit进行分块加密
    public static final int DEFAULT_BUFFERSIZE = (DEFAULT_KEY_SIZE / 8) - 11;// 当前秘钥支持加密的最大字节数
    public static final String public_key = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2oWwy1PDMDxhcWNnaEkk0WojZqzfv7GTSVdXeKMlpZXCMehFHusQNrJhK4mYTf6bXjSBxeI8oxTKkewpyU1FnpZNcCO4cBnQ5U+lUjAdBIqooZyk568EgXD+FgZJw0RqdGrW9mRelp4Wh0eyCiRP3cR4h9SuyGyr3w6V1gn6rMGziagxfXt0zy4xMgL9p99fxIUz69IFLL4mtTNjJtt8bctsNsW9dSdNeLH/XvqtaN819wwgqSrww3JJvxzrcPGkkOpSZEgrDKDczVlzw8zKyccNOiWqFnDzyFSgbuI8JJveIjWAwexs5VU9ocUxKhwFxJxPTu72DBA2lUC2mCt6cwIDAQAB";
    public static final String  private_key = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDahbDLU8MwPGFxY2doSSTRaiNmrN+/sZNJV1d4oyWllcIx6EUe6xA2smEriZhN/pteNIHF4jyjFMqR7CnJTUWelk1wI7hwGdDlT6VSMB0EiqihnKTnrwSBcP4WBknDRGp0atb2ZF6WnhaHR7IKJE/dxHiH1K7IbKvfDpXWCfqswbOJqDF9e3TPLjEyAv2n31/EhTPr0gUsvia1M2Mm23xty2w2xb11J014sf9e+q1o3zX3DCCpKvDDckm/HOtw8aSQ6lJkSCsMoNzNWXPDzMrJxw06JaoWcPPIVKBu4jwkm94iNYDB7GzlVT2hxTEqHAXEnE9O7vYMEDaVQLaYK3pzAgMBAAECggEAdjEvQZppjVJrRgAE80P0lQv6X9OLJcyvJFEIb6iWeSw6H/JISIPNfjgXFIxUg4L9mAOAWX6XW4GoWyrIIygXSsJy2f+IB6H++biNa5m4aDdzJA5spx9jqXtrApCeHu6HQbZz1ErPWlnhR4RAyPmA9SsKIjWn36HfiEMESgOVwQ/3bp4SDmSkFiJ41eA3r5YmalE4E0CxCkPM/ROvvqUJU4UHp/y+hHB6KJ6Nko8DpUs7TyFy+o4zo74jAKnDFl2IyV4cUwpdi9CFE5nr4xZXCg7cbvOHItbNCokf+cJ97lnrQhVGjMLmdwI3NV0oNDyHtn9NJmgdnirZxoawq36pwQKBgQD7UeqYZMfwrq1tCOSC8IyrIBhtWz0wqcRwclyGV4cEnAihV1ps4B2MWuNvLLCYVQ4itwWXYc0RvhU/S7hpF275s5rO6FwvB++hhMNrudPc/M/ljTik1cz75AtYOLDZTCcN9GfxAJLaJXPlxwSlxatE9u3nzbmagXjFKiLs9PZVEwKBgQDel2wDTPR3v/94WScMQZrW5nr8XZpEJn+MlWHo8qAtUAzh2JAFU7yCnbnVqEWTBUAunKDe45BaFcfg4c/uhx7STgh497l0anNVCVezmxy9/OCTRzX2bEinUfOuwiciDsKN3bTi7m064wDdqRODuD1j6coU7g6niXYoMtThL/LRIQKBgGgNjHG4GEgAKnGgYuwLqFIZocN1KSqCv4BG+SPuDUrNR411W00EpXc9EjkvaZZIcOfSmxAIQB1+c9GXCi0ItLvRruDHt5MJWB+pljd94sf2LCVAiRlGI+6OhlvqbN4q92iBrp9Lu4FyTD/wXG4+HyEYk3uL47KitFv9jCRLb8ndAoGBAKDOn/fadpq0mGlnbvBJzQUHyT3cmYA2l9sGaI+UCOfzdvsKKzHOBtgN/p0+TdUi6/VArm+X00dhiN8MA938u+WO/kv2G4LhDKUYdMWKf785mzyLK471N5+5cuSD2yWdqCw5SV7QhRUPviZk6XY1ehReZ+GrAedDRZtQ7b4pl7BBAoGAHP1hd00ELLUrf0sfnsi+tEu+nyooQhpiEhU+QLlpLogc4HhkujVyNeCHtzULck3uvr4M6hD92sbhNEMcXZWjjWKELCBvzJKV0wXBx1YDn7y4sHmj5IlqeMMij2R1z+xU4VSyqypscBBdAgxWPki4w8W22SBij4IaJY/+nfln4ww=";

    public static byte[] decryptBASE64(String key) throws Exception {
        return Base64.decode(key, Base64.DEFAULT);
    }

    public static String encryptBASE64(byte[] key) throws Exception {
        return Base64.encodeToString(key, Base64.DEFAULT);
    }

    /**
     * 随机生成RSA密钥对
     *
     * @param keyLength 密钥长度，范围：512～2048
     *                  一般1024
     * @return
     */
    public static KeyPair generateRSAKeyPair(int keyLength) {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(RSA);
            kpg.initialize(keyLength);
            return kpg.genKeyPair();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 用公钥对字符串进行加密
     *
     * @param data 原文
     */
    public static byte[] encryptByPublicKey(byte[] data, byte[] publicKey) throws Exception {
        // 得到公钥
        byte[] decoded = Base64.decode(publicKey, Base64.DEFAULT);
        RSAPublicKey keyPublic = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(decoded));
        // 加密数据
        Cipher cp = Cipher.getInstance(ECB_PKCS1_PADDING);
        cp.init(Cipher.ENCRYPT_MODE, keyPublic);
        return cp.doFinal(data);
    }

    /**
     * 私钥加密
     *
     * @param data       待加密数据
     * @param privateKey 密钥
     * @return byte[] 加密数据
     */
    public static byte[] encryptByPrivateKey(byte[] data, byte[] privateKey) throws Exception {
        // 得到私钥
        byte[] decoded = Base64.decode(privateKey, Base64.DEFAULT);
        RSAPrivateKey keyPrivate = (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(decoded));
        // 数据加密
        Cipher cipher = Cipher.getInstance(ECB_PKCS1_PADDING);
        cipher.init(Cipher.ENCRYPT_MODE, keyPrivate);
        return cipher.doFinal(data);
    }

    /**
     * 公钥解密
     *
     * @param data      待解密数据
     * @param publicKey 密钥
     * @return byte[] 解密数据
     */
    public static byte[] decryptByPublicKey(byte[] data, byte[] publicKey) throws Exception {
        // 得到公钥
        byte[] decoded = Base64.decode(publicKey, Base64.DEFAULT);
        RSAPublicKey keyPublic = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(decoded));
        // 数据解密
        Cipher cipher = Cipher.getInstance(ECB_PKCS1_PADDING);
        cipher.init(Cipher.DECRYPT_MODE, keyPublic);
        return cipher.doFinal(data);
    }

    /**
     * 使用私钥进行解密
     */
    public static byte[] decryptByPrivateKey(byte[] encrypted, byte[] privateKey) throws Exception {
        // 得到私钥
        byte[] decoded = Base64.decode(privateKey, Base64.DEFAULT);
        RSAPrivateKey keyPrivate = (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(decoded));

        // 解密数据
        Cipher cp = Cipher.getInstance(ECB_PKCS1_PADDING);
        cp.init(Cipher.DECRYPT_MODE, keyPrivate);
        byte[] arr = cp.doFinal(encrypted);
        return arr;
    }

    /**
     * 用公钥对字符串进行分段加密
     */
    public static byte[] encryptByPublicKeyForSpilt(byte[] data, byte[] publicKey) throws Exception {
        int dataLen = data.length;
        if (dataLen <= DEFAULT_BUFFERSIZE) {
            return encryptByPublicKey(data, publicKey);
        }
        List<Byte> allBytes = new ArrayList<Byte>(2048);
        int bufIndex = 0;
        int subDataLoop = 0;
        byte[] buf = new byte[DEFAULT_BUFFERSIZE];
        for (int i = 0; i < dataLen; i++) {
            buf[bufIndex] = data[i];
            if (++bufIndex == DEFAULT_BUFFERSIZE || i == dataLen - 1) {
                subDataLoop++;
                if (subDataLoop != 1) {
                    for (byte b : DEFAULT_SPLIT) {
                        allBytes.add(b);
                    }
                }
                byte[] encryptBytes = encryptByPublicKey(buf, publicKey);
                for (byte b : encryptBytes) {
                    allBytes.add(b);
                }
                bufIndex = 0;
                if (i == dataLen - 1) {
                    buf = null;
                } else {
                    buf = new byte[Math.min(DEFAULT_BUFFERSIZE, dataLen - i - 1)];
                }
            }
        }
        byte[] bytes = new byte[allBytes.size()];
        {
            int i = 0;
            for (Byte b : allBytes) {
                bytes[i++] = b.byteValue();
            }
        }
        return bytes;
    }



    /**
     * 使用私钥分段加密
     *
     * @param data       要加密的原始数据
     * @param privateKey 秘钥
     */
    public static byte[] encryptByPrivateKeyForSpilt(byte[] data, byte[] privateKey) throws Exception {
        int dataLen = data.length;
        if (dataLen <= DEFAULT_BUFFERSIZE) {
            return encryptByPrivateKey(data, privateKey);
        }
        List<Byte> allBytes = new ArrayList<Byte>(2048);
        int bufIndex = 0;
        int subDataLoop = 0;
        byte[] buf = new byte[DEFAULT_BUFFERSIZE];
        for (int i = 0; i < dataLen; i++) {
            buf[bufIndex] = data[i];
            if (++bufIndex == DEFAULT_BUFFERSIZE || i == dataLen - 1) {
                subDataLoop++;
                if (subDataLoop != 1) {
                    for (byte b : DEFAULT_SPLIT) {
                        allBytes.add(b);
                    }
                }
                byte[] encryptBytes = encryptByPrivateKey(buf, privateKey);
                for (byte b : encryptBytes) {
                    allBytes.add(b);
                }
                bufIndex = 0;
                if (i == dataLen - 1) {
                    buf = null;
                } else {
                    buf = new byte[Math.min(DEFAULT_BUFFERSIZE, dataLen - i - 1)];
                }
            }
        }
        byte[] bytes = new byte[allBytes.size()];
        {
            int i = 0;
            for (Byte b : allBytes) {
                bytes[i++] = b.byteValue();
            }
        }
        return bytes;
    }

    /**
     * 公钥分段解密
     *
     * @param encrypted 待解密数据
     * @param publicKey 密钥
     */
    public static byte[] decryptByPublicKeyForSpilt(byte[] encrypted, byte[] publicKey) throws Exception {
        int splitLen = DEFAULT_SPLIT.length;
        if (splitLen <= 0) {
            return decryptByPublicKey(encrypted, publicKey);
        }
        int dataLen = encrypted.length;
        List<Byte> allBytes = new ArrayList<Byte>(1024);
        int latestStartIndex = 0;
        for (int i = 0; i < dataLen; i++) {
            byte bt = encrypted[i];
            boolean isMatchSplit = false;
            if (i == dataLen - 1) {
                // 到data的最后了
                byte[] part = new byte[dataLen - latestStartIndex];
                System.arraycopy(encrypted, latestStartIndex, part, 0, part.length);
                byte[] decryptPart = decryptByPublicKey(part, publicKey);
                for (byte b : decryptPart) {
                    allBytes.add(b);
                }
                latestStartIndex = i + splitLen;
                i = latestStartIndex - 1;
            } else if (bt == DEFAULT_SPLIT[0]) {
                // 这个是以split[0]开头
                if (splitLen > 1) {
                    if (i + splitLen < dataLen) {
                        // 没有超出data的范围
                        for (int j = 1; j < splitLen; j++) {
                            if (DEFAULT_SPLIT[j] != encrypted[i + j]) {
                                break;
                            }
                            if (j == splitLen - 1) {
                                // 验证到split的最后一位，都没有break，则表明已经确认是split段
                                isMatchSplit = true;
                            }
                        }
                    }
                } else {
                    // split只有一位，则已经匹配了
                    isMatchSplit = true;
                }
            }
            if (isMatchSplit) {
                byte[] part = new byte[i - latestStartIndex];
                System.arraycopy(encrypted, latestStartIndex, part, 0, part.length);
                byte[] decryptPart = decryptByPublicKey(part, publicKey);
                for (byte b : decryptPart) {
                    allBytes.add(b);
                }
                latestStartIndex = i + splitLen;
                i = latestStartIndex - 1;
            }
        }
        byte[] bytes = new byte[allBytes.size()];
        {
            int i = 0;
            for (Byte b : allBytes) {
                bytes[i++] = b.byteValue();
            }
        }
        return bytes;
    }

    /**
     * 使用私钥分段解密
     */
    public static byte[] decryptByPrivateKeyForSpilt(byte[] encrypted, byte[] privateKey) throws Exception {
        int splitLen = DEFAULT_SPLIT.length;
        if (splitLen <= 0) {
            return decryptByPrivateKey(encrypted, privateKey);
        }
        int dataLen = encrypted.length;
        List<Byte> allBytes = new ArrayList<Byte>(1024);
        int latestStartIndex = 0;
        for (int i = 0; i < dataLen; i++) {
            byte bt = encrypted[i];
            boolean isMatchSplit = false;
            if (i == dataLen - 1) {
                // 到data的最后了
                byte[] part = new byte[dataLen - latestStartIndex];
                System.arraycopy(encrypted, latestStartIndex, part, 0, part.length);
                byte[] decryptPart = decryptByPrivateKey(part, privateKey);
                for (byte b : decryptPart) {
                    allBytes.add(b);
                }
                latestStartIndex = i + splitLen;
                i = latestStartIndex - 1;
            } else if (bt == DEFAULT_SPLIT[0]) {
                // 这个是以split[0]开头
                if (splitLen > 1) {
                    if (i + splitLen < dataLen) {
                        // 没有超出data的范围
                        for (int j = 1; j < splitLen; j++) {
                            if (DEFAULT_SPLIT[j] != encrypted[i + j]) {
                                break;
                            }
                            if (j == splitLen - 1) {
                                // 验证到split的最后一位，都没有break，则表明已经确认是split段
                                isMatchSplit = true;
                            }
                        }
                    }
                } else {
                    // split只有一位，则已经匹配了
                    isMatchSplit = true;
                }
            }
            if (isMatchSplit) {
                byte[] part = new byte[i - latestStartIndex];
                System.arraycopy(encrypted, latestStartIndex, part, 0, part.length);
                byte[] decryptPart = decryptByPrivateKey(part, privateKey);
                for (byte b : decryptPart) {
                    allBytes.add(b);
                }
                latestStartIndex = i + splitLen;
                i = latestStartIndex - 1;
            }
        }
        byte[] bytes = new byte[allBytes.size()];
        {
            int i = 0;
            for (Byte b : allBytes) {
                bytes[i++] = b.byteValue();
            }
        }
        return bytes;
    }

    /**
     * 用公钥对字符串进行分段加密
     */
    public static String encryptByPublicKeyForSpiltStr(String data, String publicKey) throws Exception {
        byte[] encryptBytes = encryptByPublicKeyForSpilt(data.getBytes("UTF-8"), publicKey.getBytes());
        return encryptBASE64(encryptBytes);
    }

    /**
     * 使用私钥分段加密
     *
     * @param data       要加密的原始数据
     * @param privateKey 秘钥
     */
    public static String encryptByPrivateKeyForSpiltStr(String data, String privateKey) throws Exception {
        byte[] encryptBytes = encryptByPrivateKeyForSpilt(data.getBytes("UTF-8"), privateKey.getBytes());
        return encryptBASE64(encryptBytes);
    }

    /**
     * 公钥分段解密
     *
     * @param encrypted 待解密数据
     * @param publicKey 密钥
     */
    public static String decryptByPublicKeyForSpiltStr(String encrypted, String publicKey) throws Exception {
        byte[] decryptBytes  = decryptByPublicKeyForSpilt(decryptBASE64(encrypted), publicKey.getBytes());
        return new String(decryptBytes,"UTF-8");
    }

    /**
     * 使用私钥分段解密
     */
    public static String decryptByPrivateKeyForSpiltStr(String encrypted, String privateKey) throws Exception {
        byte[] decryptBytes = decryptByPrivateKeyForSpilt(decryptBASE64(encrypted), privateKey.getBytes());
        return new String(decryptBytes,"UTF-8");
    }
}