import static java.nio.charset.StandardCharsets.UTF_8;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class RSAUtil {

    // original
    private static String publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCgFGVfrY4jQSoZQWWygZ83roKXWD4YeT2x2p41dGkPixe73rT2IW04glagN2vgoZoHuOPqa5and6kAmK2ujmCHu6D1auJhE2tXP+yLkpSiYMQucDKmCsWMnW9XlC5K7OSL77TXXcfvTvyZcjObEz6LIBRzs6+FqpFbUO9SJEfh6wIDAQAB";
    private static String privateKey = "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAKAUZV+tjiNBKhlBZbKBnzeugpdYPhh5PbHanjV0aQ+LF7vetPYhbTiCVqA3a+Chmge44+prlqd3qQCYra6OYIe7oPVq4mETa1c/7IuSlKJgxC5wMqYKxYydb1eULkrs5IvvtNddx+9O/JlyM5sTPosgFHOzr4WqkVtQ71IkR+HrAgMBAAECgYAkQLo8kteP0GAyXAcmCAkA2Tql/8wASuTX9ITD4lsws/VqDKO64hMUKyBnJGX/91kkypCDNF5oCsdxZSJgV8owViYWZPnbvEcNqLtqgs7nj1UHuX9S5yYIPGN/mHL6OJJ7sosOd6rqdpg6JRRkAKUV+tmN/7Gh0+GFXM+ug6mgwQJBAO9/+CWpCAVoGxCA+YsTMb82fTOmGYMkZOAfQsvIV2v6DC8eJrSa+c0yCOTa3tirlCkhBfB08f8U2iEPS+Gu3bECQQCrG7O0gYmFL2RX1O+37ovyyHTbst4s4xbLW4jLzbSoimL235lCdIC+fllEEP96wPAiqo6dzmdH8KsGmVozsVRbAkB0ME8AZjp/9Pt8TDXD5LHzo8mlruUdnCBcIo5TMoRG2+3hRe1dHPonNCjgbdZCoyqjsWOiPfnQ2Brigvs7J4xhAkBGRiZUKC92x7QKbqXVgN9xYuq7oIanIM0nz/wq190uq0dh5Qtow7hshC/dSK3kmIEHe8z++tpoLWvQVgM538apAkBoSNfaTkDZhFavuiVl6L8cWCoDcJBItip8wKQhXwHp0O3HLg10OEd14M58ooNfpgt+8D8/8/2OOFaR0HzA+2Dm";

    // private static String publicKey =
    // "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuP311rXbo8gXgeD+xqHeFRP0H5djzpIO9TEuGXtfIw7z2fKvu5dxUCgXAjKrYH5iHoHZA4FiM138uFrAYiiILi++5Tz0GpNpQ900Qeci4az4Hzy864kg6rFucpgAy0lOLjiPaUcRSfAfg38LM2UaEoFpKE7fQrNcXYKOiSC6/OoEviBkeWyDjYRi8cS29T7wZy4r8TbwWzXNxMfq42jhoUz9U4RTHWd3asM3olv+MltsBm8gEnmpTXmxUYrDTLSLWbddPxdE/rfLU5aalzTx1yK5MwNHhcDfqcgmIA1XOgRe1+6PYpm9NXLEBF8mFldIuhdz2FWFvL5c7mzQ31UySwIDAQAB";
    // private static String privateKey =
    // "MIIEpQIBAAKCAQEAuP311rXbo8gXgeD+xqHeFRP0H5djzpIO9TEuGXtfIw7z2fKvu5dxUCgXAjKrYH5iHoHZA4FiM138uFrAYiiILi++5Tz0GpNpQ900Qeci4az4Hzy864kg6rFucpgAy0lOLjiPaUcRSfAfg38LM2UaEoFpKE7fQrNcXYKOiSC6/OoEviBkeWyDjYRi8cS29T7wZy4r8TbwWzXNxMfq42jhoUz9U4RTHWd3asM3olv+MltsBm8gEnmpTXmxUYrDTLSLWbddPxdE/rfLU5aalzTx1yK5MwNHhcDfqcgmIA1XOgRe1+6PYpm9NXLEBF8mFldIuhdz2FWFvL5c7mzQ31UySwIDAQABAoIBAQCX1WmXhr/1V19j7GVwZp6+shfmbf0vKNY6DNmHdKkLP1SKCBSQZaZNYfowhaH/mvuximWx6NnOy0+HiITqi9XqAqotwK+huGfnmYEwriMFE1C7YsC0mWJ4/pRmXbgZIduXODkM8ZWRGBLlfLqWvl593dWPjdzVBB3FakjO6BxRQ+FmGRlj3/JEJ2fWFhss0p3O+JRAOiRzlFduqTMHvtBqLilPg/6nBPR9aIeq1OzsXWTu496selwnGiSDIECQYR3jDsw4c341euyDTPkyMLrcHbGnskdwVgXKpvgwAmheA7hDnOcWuOIOUCmdk4wHSsOx1lw6GAN8QQVSYGQqD4jhAoGBAPnjljWMSONumuyvr3D/exynzRpJnuiiRqf82CaDuhovPwgY+Vhni1eSpE1ONGQSMQaB86JyIX1hfsVoUXg7G6h3Lys5Opxxb6SNvqgi6BrDrjzzDWFJV7lMWUNp/lddNnLG05bOWj2Sqnz2RO3jYpuZr0tHe1BO9VWgdXRgMKWJAoGBAL2EFyUqTHWLRah9WuUkmNHOyavjeQ3CKdCV7tODYLoFC8L2iVnS6/S7tAR6pQm5URVEBPCeHycbpbuZPuke0eabFTmTG7mOittsX0J69DVaSf7xFMC/zBDDqH8/as23kU6YkSsa5Ze4s9ApKHEpy5IZyB+ng8hiN8c9CMIwrHgzAoGBALP1p65mmfNYKzA7EbDh/GpVmgrNbCiC/TlriMqr4PGMhusw+RkmcJ4fmD2oDWjoBPB309pwMRgXh3FpQArDHpcDRi/tpf0WYF10SxLRGLB1rdxs+XzPkeJ7TmmTQrzt/xFHiQe5Ehn3rtoRjPB46gG++xPOpcrfIiWJSi0GPOJpAoGAGH+y3kMRj0BpyNYroeORPc4Vk/rb80NeVHCNZxpcrq9oTdPA/bOefQymwM15+D/Uk4MvgEtwi4WvbwjocQpi6AS0QbUaqGoc2TCxP87VMvBxEFvp6uDgaGpipdB05hMM3bQrT/8yHuLpm8c2Syqz/jcG/9CP4J+RxlfFghT4trECgYEAzrDsOScAZTBtBqUSbCQ8YJI/+onS906ZRu+r5Qood4BmZYZv6KRgX19e5EiIQmoFutHJdfwcEANY1N0pObGhT4Bn13/Xo/sEWx7Aoa8cYG6AMWFXDPW8aWXShvTojVm7ZzDmIgKkw1k6AWzidn1kBVunFf22YoSYo/45FgFqkII=";

    public static PublicKey getPublicKey(String base64PublicKey) {
        PublicKey publicKey = null;
        try {
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(base64PublicKey.getBytes()));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            publicKey = keyFactory.generatePublic(keySpec);
            return publicKey;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return publicKey;
    }

    public static PrivateKey getPrivateKey(String base64PrivateKey) {
        PrivateKey privateKey = null;
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64PrivateKey.getBytes()));
        KeyFactory keyFactory = null;
        try {
            keyFactory = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        try {
            privateKey = keyFactory.generatePrivate(keySpec);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return privateKey;
    }

    public static byte[] encrypt(String data, String publicKey) throws BadPaddingException, IllegalBlockSizeException,
            InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, getPublicKey(publicKey));
        return cipher.doFinal(data.getBytes());
    }

    public static String decrypt(byte[] data, PrivateKey privateKey) throws NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(cipher.doFinal(data));
    }

    public static String decrypt(String data, String base64PrivateKey) throws IllegalBlockSizeException,
            InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        return decrypt(Base64.getDecoder().decode(data.getBytes()), getPrivateKey(base64PrivateKey));
    }

    public static String RSASign(String plainText, PrivateKey privateKey) throws Exception {
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(privateKey);
        privateSignature.update(plainText.getBytes(UTF_8));

        byte[] signature = privateSignature.sign();

        return Base64.getEncoder().encodeToString(signature);
    }

    public static boolean RSAVerify(String plainText, String signature, PublicKey publicKey) throws Exception {
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(publicKey);
        publicSignature.update(plainText.getBytes(UTF_8));

        byte[] signatureBytes = Base64.getDecoder().decode(signature);

        return publicSignature.verify(signatureBytes);
    }

    public static void main(String[] args) throws IllegalBlockSizeException, InvalidKeyException,
            NoSuchPaddingException, BadPaddingException, Exception {
        try {

            String encryptedString = Base64.getEncoder().encodeToString(encrypt("hello world", publicKey));
            System.out.println("RSA encrypt:" + encryptedString);
            String decryptedString = decrypt(encryptedString, privateKey);
            System.out.println("RSA decrypt:" + decryptedString);

            // Sign

            String plainText = "hello";
            String signx = RSASign(plainText, getPrivateKey(privateKey));
            System.out.println("RSA Sign:" + signx);

            // Verify

            boolean verify = RSAVerify(plainText, signx, getPublicKey(publicKey));
            System.out.println("RSAVerify:" + verify);

            // read file

            String privateKeyContent = new String(
                    Files.readAllBytes(Paths.get(ClassLoader.getSystemResource("privateKey.pem").toURI())));
            String publicKeyContent = new String(
                    Files.readAllBytes(Paths.get(ClassLoader.getSystemResource("publicKey.pem").toURI())));

            privateKeyContent = privateKeyContent.replaceAll("\\r|\\n", "")
                    .replace("-----BEGIN RSA PRIVATE KEY-----", "").replaceAll("-----END RSA PRIVATE KEY-----", "");
            publicKeyContent = publicKeyContent.replaceAll("\\r|\\n", "").replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "");

            System.out.println("--------------privateKey:-------------- ");
            System.out.println(privateKeyContent);

            System.out.println("--------------publicKey:-------------- ");
            System.out.println(publicKeyContent);

            String signx2 = RSASign(plainText, getPrivateKey(privateKeyContent));
            System.out.println("RSA Sign:" + signx2);


            boolean verify2 = RSAVerify(plainText, signx2, getPublicKey(publicKeyContent));
            System.out.println("RSAVerify2:" + verify2);


        } catch (NoSuchAlgorithmException e) {
            System.err.println(e.getMessage());
        }

    }
}