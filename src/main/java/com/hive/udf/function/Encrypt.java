package com.hive.udf.function;

import org.apache.commons.lang3.StringUtils;
import org.apache.hadoop.hive.ql.exec.Description;
import org.apache.hadoop.hive.ql.exec.UDFArgumentException;
import org.apache.hadoop.hive.ql.metadata.HiveException;
import org.apache.hadoop.hive.ql.udf.generic.GenericUDF;
import org.apache.hadoop.hive.serde2.objectinspector.ObjectInspector;
import org.apache.hadoop.hive.serde2.objectinspector.primitive.IntObjectInspector;
import org.apache.hadoop.hive.serde2.objectinspector.primitive.PrimitiveObjectInspectorFactory;
import org.apache.hadoop.hive.serde2.objectinspector.primitive.StringObjectInspector;
import org.apache.kerby.util.Base64;
import org.springframework.stereotype.Component;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

@Description(
        name="Encrypt",
        value="input data is int or string",
        extended="select Encrypt(data) from table limit 10;"
)
@Component
public class Encrypt extends GenericUDF{

    private final static String KEY = "11111111111111111111111111111111";
    private final static String ALG = "AES/CBC/PKCS5Padding";
    private final static String IV = KEY.substring(0, 16);

    @Override
    public ObjectInspector initialize(ObjectInspector[] arguments) throws UDFArgumentException {
        if (arguments.length != 1){
            throw new UDFArgumentException("argument length is 1");
        }

        ObjectInspector inspector = arguments[0];
        if (!(inspector instanceof IntObjectInspector || inspector instanceof StringObjectInspector)){
            throw new UDFArgumentException("argument type is Integer or String");
        }
        return PrimitiveObjectInspectorFactory.javaStringObjectInspector;
    }

    @Override
    public Object evaluate(DeferredObject[] arguments) throws HiveException{
        return encryptAES256(String.valueOf(arguments[0].get()));
    }

    @Override
    public String getDisplayString(String[] errInfo) {
        return "error : " + errInfo[0];
    }

    public static String encryptAES256(String text){
        String result = null;
        try{
            result = StringUtils.replace(Base64.encodeBase64String(getCipher(text,Cipher.ENCRYPT_MODE).doFinal(text.getBytes(StandardCharsets.UTF_8))), System.getProperty("line.separator"), "");
        }catch (GeneralSecurityException e){
            System.out.println("security processing exception");
        }
        return result;
    }

    public static String decryptAES256(String text){
        String result = null;
        try{
            result = new String(getCipher(text, Cipher.DECRYPT_MODE).doFinal(Base64.decodeBase64(text)), StandardCharsets.UTF_8);
        }catch (GeneralSecurityException e){
            System.out.println("security processing exception");
        }
        return result;
    }

    public static Cipher getCipher(String text, int cipherMode) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(ALG);
        SecretKeySpec keySpec = new SecretKeySpec(KEY.getBytes(), "AES");
        IvParameterSpec ivParamSpec = new IvParameterSpec(IV.getBytes());
        cipher.init(cipherMode, keySpec, ivParamSpec);
        return cipher;
    }
}
