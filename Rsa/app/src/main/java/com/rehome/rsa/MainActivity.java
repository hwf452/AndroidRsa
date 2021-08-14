package com.rehome.rsa;

import androidx.appcompat.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;

import java.util.Map;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        try {
            Map<String, Object> key = RSAUtils.initKey();
            String publicKey = RSAUtils.getPublicKey(key);
            String privateKey = RSAUtils.getPrivateKey(key);
            Log.i("rsa",publicKey);
            Log.i("rsa",privateKey);
            String signbypub = RSAUtils.encryptBASE64(RSAUtils.encryptByPublicKey("wenfei".getBytes(),publicKey));
            Log.i("RSA",signbypub);
            byte[] ecodeByte = RSAUtils.decryptBASE64(signbypub);
            String decodeStr = new String(RSAUtils.decryptByPrivateKey(ecodeByte,privateKey));
            Log.i("RSA",decodeStr);

        } catch (Exception e) {
            e.printStackTrace();
        }

        try {
            Map<String, Object> key = RSAUtils.initKey();
            String publicKey = RSAUtils.getPublicKey(key);
            String privateKey = RSAUtils.getPrivateKey(key);
            String signbypub = RSAUtils.encryptBASE64(RSAUtils.encryptByPublicKey("wenfei".getBytes(),RSAUtils.public_key));
            byte[] ecodeByte = RSAUtils.decryptBASE64(signbypub);
            String decodeStr = new String(RSAUtils.decryptByPrivateKey(ecodeByte,RSAUtils.private_key));
            Log.i("rsa",publicKey);
            Log.i("rsa",privateKey);
            Log.i("RSA",signbypub);
            Log.i("RSA",decodeStr);
        } catch (Exception e) {
            e.printStackTrace();
        }

        try {
            String messageEn= RSAAndroid.encryptByPublicKeyForSpiltStr("8月8日晚，东京国立竞技场的奥运圣火熄灭，场内电子屏上打出了“ARIGATO”（日语“谢谢”的罗马字）。57年前的那一夜，东京奥运会闭幕式大屏上留下的是“SAYONARA”（日语“再见”罗马字）。从告别到感谢，本届奥运会对日本而言，原本是一场赌上国运的体育盛事，而现实却朝着与理想相反的方向一路狂奔。8月8日晚，东京国立竞技场的奥运圣火熄灭，场内电子屏上打出了“ARIGATO”（日语“谢谢”的罗马字）。57年前的那一夜，东京奥运会闭幕式大屏上留下的是“SAYONARA”（日语“再见”罗马字）。从告别到感谢，本届奥运会对日本而言，原本是一场赌上国运的体育盛事，而现实却朝着与理想相反的方向一路狂奔。8月8日晚，东京国立竞技场的奥运圣火熄灭，场内电子屏上打出了“ARIGATO”（日语“谢谢”的罗马字）。57年前的那一夜，东京奥运会闭幕式大屏上留下的是“SAYONARA”（日语“再见”罗马字）。从告别到感谢，本届奥运会对日本而言，原本是一场赌上国运的体育盛事，而现实却朝着与理想相反的方向一路狂奔。8月8日晚，东京国立竞技场的奥运圣火熄灭，场内电子屏上打出了“ARIGATO”（日语“谢谢”的罗马字）。57年前的那一夜，东京奥运会闭幕式大屏上留下的是“SAYONARA”（日语“再见”罗马字）。从告别到感谢，本届奥运会对日本而言，原本是一场赌上国运的体育盛事，而现实却朝着与理想相反的方向一路狂奔。8月8日晚，东京国立竞技场的奥运圣火熄灭，场内电子屏上打出了“ARIGATO”（日语“谢谢”的罗马字）。57年前的那一夜，东京奥运会闭幕式大屏上留下的是“SAYONARA”（日语“再见”罗马字）。从告别到感谢，本届奥运会对日本而言，原本是一场赌上国运的体育盛事，而现实却朝着与理想相反的方向一路狂奔。8月8日晚，东京国立竞技场的奥运圣火熄灭，场内电子屏上打出了“ARIGATO”（日语“谢谢”的罗马字）。57年前的那一夜，东京奥运会闭幕式大屏上留下的是“SAYONARA”（日语“再见”罗马字）。从告别到感谢，本届奥运会对日本而言，原本是一场赌上国运的体育盛事，而现实却朝着与理想相反的方向一路狂奔。8月8日晚，东京国立竞技场的奥运圣火熄灭，场内电子屏上打出了“ARIGATO”（日语“谢谢”的罗马字）。57年前的那一夜，东京奥运会闭幕式大屏上留下的是“SAYONARA”（日语“再见”罗马字）。从告别到感谢，本届奥运会对日本而言，原本是一场赌上国运的体育盛事，而现实却朝着与理想相反的方向一路狂奔。8月8日晚，东京国立竞技场的奥运圣火熄灭，场内电子屏上打出了“ARIGATO”（日语“谢谢”的罗马字）。57年前的那一夜，东京奥运会闭幕式大屏上留下的是“SAYONARA”（日语“再见”罗马字）。从告别到感谢，本届奥运会对日本而言，原本是一场赌上国运的体育盛事，而现实却朝着与理想相反的方向一路狂奔。8月8日晚，东京国立竞技场的奥运圣火熄灭，场内电子屏上打出了“ARIGATO”（日语“谢谢”的罗马字）。57年前的那一夜，东京奥运会闭幕式大屏上留下的是“SAYONARA”（日语“再见”罗马字）。从告别到感谢，本届奥运会对日本而言，原本是一场赌上国运的体育盛事，而现实却朝着与理想相反的方向一路狂奔。8月8日晚，东京国立竞技场的奥运圣火熄灭，场内电子屏上打出了“ARIGATO”（日语“谢谢”的罗马字）。57年前的那一夜，东京奥运会闭幕式大屏上留下的是“SAYONARA”（日语“再见”罗马字）。从告别到感谢，本届奥运会对日本而言，原本是一场赌上国运的体育盛事，而现实却朝着与理想相反的方向一路狂奔。8月8日晚，东京国立竞技场的奥运圣火熄灭，场内电子屏上打出了“ARIGATO”（日语“谢谢”的罗马字）。57年前的那一夜，东京奥运会闭幕式大屏上留下的是“SAYONARA”（日语“再见”罗马字）。从告别到感谢，本届奥运会对日本而言，原本是一场赌上国运的体育盛事，而现实却朝着与理想相反的方向一路狂奔。", RSAAndroid.public_key);
            System.out.println("message En:"+messageEn);
            String messageDe = RSAAndroid.decryptByPrivateKeyForSpiltStr(messageEn, RSAAndroid.private_key);
            System.out.println("message content:"+messageDe);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}