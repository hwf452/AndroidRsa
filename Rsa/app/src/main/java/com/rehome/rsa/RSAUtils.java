package com.rehome.rsa;

import android.util.Base64;
import android.util.Log;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.Cipher;

/**
 *
 *  常规加密，加密内容不能超过2048，超过的话会报错。
 */

public class RSAUtils {

    /**RSA算法*/
    public static final String RSA = "RSA";
    /**加密方式，android的*/
//  public static final String TRANSFORMATION = "RSA/None/NoPadding";
    /**加密方式，标准jdk的*/
    public static final String TRANSFORMATION = "RSA/ECB/PKCS1Padding";

    public static final String SIGNATURE_ALGORITHM = "MD5withRSA";

    private static final String PUBLIC_KEY = "RSAPublicKey";
    private static final String PRIVATE_KEY = "RSAPrivateKey";

    public static final String public_key = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2oWwy1PDMDxhcWNnaEkk0WojZqzfv7GTSVdXeKMlpZXCMehFHusQNrJhK4mYTf6bXjSBxeI8oxTKkewpyU1FnpZNcCO4cBnQ5U+lUjAdBIqooZyk568EgXD+FgZJw0RqdGrW9mRelp4Wh0eyCiRP3cR4h9SuyGyr3w6V1gn6rMGziagxfXt0zy4xMgL9p99fxIUz69IFLL4mtTNjJtt8bctsNsW9dSdNeLH/XvqtaN819wwgqSrww3JJvxzrcPGkkOpSZEgrDKDczVlzw8zKyccNOiWqFnDzyFSgbuI8JJveIjWAwexs5VU9ocUxKhwFxJxPTu72DBA2lUC2mCt6cwIDAQAB";
    public static final String  private_key = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDahbDLU8MwPGFxY2doSSTRaiNmrN+/sZNJV1d4oyWllcIx6EUe6xA2smEriZhN/pteNIHF4jyjFMqR7CnJTUWelk1wI7hwGdDlT6VSMB0EiqihnKTnrwSBcP4WBknDRGp0atb2ZF6WnhaHR7IKJE/dxHiH1K7IbKvfDpXWCfqswbOJqDF9e3TPLjEyAv2n31/EhTPr0gUsvia1M2Mm23xty2w2xb11J014sf9e+q1o3zX3DCCpKvDDckm/HOtw8aSQ6lJkSCsMoNzNWXPDzMrJxw06JaoWcPPIVKBu4jwkm94iNYDB7GzlVT2hxTEqHAXEnE9O7vYMEDaVQLaYK3pzAgMBAAECggEAdjEvQZppjVJrRgAE80P0lQv6X9OLJcyvJFEIb6iWeSw6H/JISIPNfjgXFIxUg4L9mAOAWX6XW4GoWyrIIygXSsJy2f+IB6H++biNa5m4aDdzJA5spx9jqXtrApCeHu6HQbZz1ErPWlnhR4RAyPmA9SsKIjWn36HfiEMESgOVwQ/3bp4SDmSkFiJ41eA3r5YmalE4E0CxCkPM/ROvvqUJU4UHp/y+hHB6KJ6Nko8DpUs7TyFy+o4zo74jAKnDFl2IyV4cUwpdi9CFE5nr4xZXCg7cbvOHItbNCokf+cJ97lnrQhVGjMLmdwI3NV0oNDyHtn9NJmgdnirZxoawq36pwQKBgQD7UeqYZMfwrq1tCOSC8IyrIBhtWz0wqcRwclyGV4cEnAihV1ps4B2MWuNvLLCYVQ4itwWXYc0RvhU/S7hpF275s5rO6FwvB++hhMNrudPc/M/ljTik1cz75AtYOLDZTCcN9GfxAJLaJXPlxwSlxatE9u3nzbmagXjFKiLs9PZVEwKBgQDel2wDTPR3v/94WScMQZrW5nr8XZpEJn+MlWHo8qAtUAzh2JAFU7yCnbnVqEWTBUAunKDe45BaFcfg4c/uhx7STgh497l0anNVCVezmxy9/OCTRzX2bEinUfOuwiciDsKN3bTi7m064wDdqRODuD1j6coU7g6niXYoMtThL/LRIQKBgGgNjHG4GEgAKnGgYuwLqFIZocN1KSqCv4BG+SPuDUrNR411W00EpXc9EjkvaZZIcOfSmxAIQB1+c9GXCi0ItLvRruDHt5MJWB+pljd94sf2LCVAiRlGI+6OhlvqbN4q92iBrp9Lu4FyTD/wXG4+HyEYk3uL47KitFv9jCRLb8ndAoGBAKDOn/fadpq0mGlnbvBJzQUHyT3cmYA2l9sGaI+UCOfzdvsKKzHOBtgN/p0+TdUi6/VArm+X00dhiN8MA938u+WO/kv2G4LhDKUYdMWKf785mzyLK471N5+5cuSD2yWdqCw5SV7QhRUPviZk6XY1ehReZ+GrAedDRZtQ7b4pl7BBAoGAHP1hd00ELLUrf0sfnsi+tEu+nyooQhpiEhU+QLlpLogc4HhkujVyNeCHtzULck3uvr4M6hD92sbhNEMcXZWjjWKELCBvzJKV0wXBx1YDn7y4sHmj5IlqeMMij2R1z+xU4VSyqypscBBdAgxWPki4w8W22SBij4IaJY/+nfln4ww=";


    public static byte[] decryptBASE64(String key) throws Exception {
        return Base64.decode(key, Base64.DEFAULT);
    }

    public static String encryptBASE64(byte[] key) throws Exception {
        return Base64.encodeToString(key, Base64.DEFAULT);
    }

    /**
     * 用私钥对信息生成数字签名
     *
     * @param data       加密数据
     * @param privateKey 私钥
     * @return
     * @throws Exception
     */
    public static String sign(byte[] data, String privateKey) throws Exception {
        // 解密由base64编码的私钥
        byte[] keyBytes = decryptBASE64(privateKey);
        // 构造PKCS8EncodedKeySpec对象
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        // KEY_ALGORITHM 指定的加密算法
        KeyFactory keyFactory = KeyFactory.getInstance(RSA);
        // 取私钥匙对象
        PrivateKey priKey = keyFactory.generatePrivate(pkcs8KeySpec);
        // 用私钥对信息生成数字签名
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(priKey);
        signature.update(data);
        return encryptBASE64(signature.sign());
    }

    /**
     * 校验数字签名
     *
     * @param data      加密数据
     * @param publicKey 公钥
     * @param sign      数字签名
     * @return 校验成功返回true 失败返回false
     * @throws Exception
     */
    public static boolean verify(byte[] data, String publicKey, String sign)
            throws Exception {
        // 解密由base64编码的公钥
        byte[] keyBytes = decryptBASE64(publicKey);
        // 构造X509EncodedKeySpec对象
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        // KEY_ALGORITHM 指定的加密算法
        KeyFactory keyFactory = KeyFactory.getInstance(RSA);
        // 取公钥匙对象
        PublicKey pubKey = keyFactory.generatePublic(keySpec);
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initVerify(pubKey);
        signature.update(data);
        // 验证签名是否正常
        return signature.verify(decryptBASE64(sign));
    }

    /**
     * 解密<br>
     * 用私钥解密
     *
     * @param data
     * @param key
     * @return
     * @throws Exception
     */
    public static byte[] decryptByPrivateKey(byte[] data, String key)
            throws Exception {
        // 对密钥解密
        byte[] keyBytes = decryptBASE64(key);
        // 取得私钥
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(RSA);
        Key privateKey = keyFactory.generatePrivate(pkcs8KeySpec);
        // 对数据解密
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }

    /**
     * 解密<br>
     * 用公钥解密
     *
     * @param data
     * @param key
     * @return
     * @throws Exception
     */
    public static byte[] decryptByPublicKey(byte[] data, String key)
            throws Exception {
        // 对密钥解密
        byte[] keyBytes = decryptBASE64(key);
        // 取得公钥
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(RSA);
        Key publicKey = keyFactory.generatePublic(x509KeySpec);
        // 对数据解密
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    /**
     * 加密<br>
     * 用公钥加密
     *
     * @param data
     * @param key
     * @return
     * @throws Exception
     */
    public static byte[] encryptByPublicKey(byte[] data, String key)
            throws Exception {
        // 对公钥解密
        byte[] keyBytes = decryptBASE64(key);
        // 取得公钥
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(RSA);
        Key publicKey = keyFactory.generatePublic(x509KeySpec);
        // 对数据加密
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    /**
     * 加密<br>
     * 用私钥加密
     *
     * @param data
     * @param key
     * @return
     * @throws Exception
     */
    public static byte[] encryptByPrivateKey(byte[] data, String key)
            throws Exception {
        // 对密钥解密
        byte[] keyBytes = decryptBASE64(key);
        // 取得私钥
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(RSA);
        Key privateKey = keyFactory.generatePrivate(pkcs8KeySpec);
        // 对数据加密
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }

    /**
     * 取得私钥
     *
     * @param keyMap
     * @return
     * @throws Exception
     */
    public static String getPrivateKey(Map<String, Object> keyMap)
            throws Exception {
        Key key = (Key) keyMap.get(PRIVATE_KEY);

        return encryptBASE64(key.getEncoded());
    }

    /**
     * 取得公钥
     *
     * @param keyMap
     * @return
     * @throws Exception
     */
    public static String getPublicKey(Map<String, Object> keyMap)
            throws Exception {
        Key key = (Key) keyMap.get(PUBLIC_KEY);
        return encryptBASE64(key.getEncoded());
    }

    /**
     * 初始化密钥
     *
     * @return
     * @throws Exception
     */
    public static Map<String, Object> initKey() throws Exception {
        KeyPairGenerator keyPairGen = KeyPairGenerator
                .getInstance(RSA);
        keyPairGen.initialize(2048);
        KeyPair keyPair = keyPairGen.generateKeyPair();
        // 公钥
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        // 私钥
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        Map<String, Object> keyMap = new HashMap<String, Object>(2);
        keyMap.put(PUBLIC_KEY, publicKey);
        keyMap.put(PRIVATE_KEY, privateKey);
        return keyMap;
    }

    public static void main(String[] args) {
        try {
            Map<String, Object> key = RSAUtils.initKey();
            String publicKey = RSAUtils.getPublicKey(key);
            String privateKey = RSAUtils.getPrivateKey(key);
            String signbypub = RSAUtils.encryptBASE64(RSAUtils.encryptByPublicKey("wenfei".getBytes(),RSAUtils.public_key));
            String ecodeStr = new String(RSAUtils.decryptByPrivateKey(signbypub.getBytes(),RSAUtils.private_key));
            Log.i("rsa",publicKey);
            Log.i("rsa",privateKey);
            Log.i("RSA",signbypub);
            Log.i("RSA",ecodeStr);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}