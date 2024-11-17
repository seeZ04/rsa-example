import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import static java.nio.charset.StandardCharsets.UTF_8;
import java.nio.file.Files;
import java.nio.file.Paths;

public class rsaencryption {
    private static String publicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzwaoB9iK1lsgmSlOd9NJr9dpvx0/kHit3/JanWxdcL1JYpod6tAMMrMdjJHMdRhXZjQIisaSl5UOHbmQQPgfN9g3PpndBSejmdWmLIf0q994d/+b2NmA7+szko4dM5Af5mK7xZDV4UbdgPwhurp/d0dDLNJAcWjFWqkSdXUfXqf+KlywXYOgSK7qRXutwoILqSmmgc3M9RmagEqmScF6VA/0dld+/rj8ts2ysNCSZL7Jv/DReJTd2EQ3tgLZ5UR1OwXyrwRMU78OAvrYKgwWLURuLxLGtSH/fujii/6JO0DA8ab/6MTDU6dmMU0slSMdlHpy720YcE3GXKrUgYSicwIDAQAB";
    private static String privateKey = "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDPBqgH2IrWWyCZKU5300mv12m/HT+QeK3f8lqdbF1wvUlimh3q0Awysx2Mkcx1GFdmNAiKxpKXlQ4duZBA+B832Dc+md0FJ6OZ1aYsh/Sr33h3/5vY2YDv6zOSjh0zkB/mYrvFkNXhRt2A/CG6un93R0Ms0kBxaMVaqRJ1dR9ep/4qXLBdg6BIrupFe63CggupKaaBzcz1GZqASqZJwXpUD/R2V37+uPy2zbKw0JJkvsm/8NF4lN3YRDe2AtnlRHU7BfKvBExTvw4C+tgqDBYtRG4vEsa1If9+6OKL/ok7QMDxpv/oxMNTp2YxTSyVIx2UenLvbRhwTcZcqtSBhKJzAgMBAAECggEBAJxYJYuPUAJj3XFtjXHWod5m6thGqVtcl8r5Rs9+J+7dNE9/njpXle6v8A/Zh7Oih1aK0yyim9BX48o0+ijmeQT+h3ICVrTu45FolM8qeW9XG65b3gFc+Q+260KxioIHROADDlU8dRllICCpyHsxHtQggC2YNsyu1+QIrQUBR4h+LvATn2kXdJK2Br/tx0NW2hmYvlY1MCU0mzRAwrDrNohsACe4Lc3SyU90rrP7NrZOMiceGjB8tdknmqZx7NJaTJySSRM57+SbcTFF2tITfRD5+RoVK/afYstK8/sMe2FJfxHw6PA7pWUNNel925G+P90N+GCU3pjU+0ZAwNv1SvECgYEA+o+9LtWxeTcB7f+WbcWnkXJxjrBgXsvIWd7ERAyxWkpG4yIyAv0iNf4UntN0Ub/nofY102iKbjk/XykhS17iBdNgABbGsRdAoRTsKewDPaUFzEE3mf1My/2RYyLsvjNdQYUgWZbyvZ0/mWNTBd6bOCZs1Bnamu8tYtBRFvSTFrkCgYEA04UCem94PzFGupqWIZVcy4MQtTCo7VrkNGy5ih/75gajR6wBABr46EIrpC7TrPPJuwUnxxzZKAeuW7/NBU8MjVFcVc4GEbauTX+YI1IwowFbepelQcAWE7o1gMFYZRFJouD5MbYQidgjFY/SLvMZ5VHX8Zcw89S0gwAtUvP7rIsCgYBSYO3XNyTpcH9u62he4OxN8q2JN04H/MH7YjVvFik9QUx7IuQEfYtA6y+GZIlK02hppJRf1HAm+yVtuQ0cRa7UMYHPpa1fzgBOtZ1Lzy/llZsJY6vPMiuMqeqiCHqDskmH4CgZrHpUgx3E5ZYHSQAJfwCq33EzHU3zvf/bJ0Aw6QKBgQCX2zdjRWIUJEF+OPuuErizV16IZu3wsj+CL8ipFLtZcsyI6UEynSq0PMVuMzw/QCtFfLcJKXnyVklkj3gW5qDBWHctFyOeVgQfmYpVWW2XqaLOic7YPJrdAOPmk2jt7pJqQJBHk0meXTEbCs1AbcHatH6PcRdxBvWt01O26Xl3bwKBgQDulUsX+Q7sa5mN9eO4VkcBUoc6G+Ag7CZedvYpi/ggCqfXhMEGLxLFHObcWi58ITxiKqoT+40ktnTJXs1XsxyX9Jux+BIjetbMGstGEgpK7OLcDhvVAZY7xOxNDV39631yywjuEzU6xu7FWHVOdpkSwWyEimlXamIOJQTkJHOkBw==";

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

    public static void main(String[] args) throws Exception {
        try {
            String encryptedString = Base64.getEncoder().encodeToString(encrypt("Dhiraj is the author", publicKey));
            System.out.println(encryptedString);
            String decryptedString = RSAUtil.decrypt(encryptedString, privateKey);
            System.out.println(decryptedString);

            String plainText = "MyGmobile";
            String signx = RSASign(plainText, getPrivateKey(privateKey));
            System.out.println("RSA Sign:" + signx);

            // Verify
            boolean verify = RSAVerify(plainText, signx, getPublicKey(publicKey));
            System.out.println("RSAVerify:" + verify);

            System.out.println("-------------------------------------------");


            String privateKeyContent = new String(
                    Files.readAllBytes(Paths.get(ClassLoader.getSystemResource("privateKey.pem").toURI())));
            String publicKeyContent = new String(
                    Files.readAllBytes(Paths.get(ClassLoader.getSystemResource("publicKey.pem").toURI())));

            privateKeyContent = privateKeyContent.replaceAll("\\r|\\n", "")
                    .replace("-----BEGIN RSA PRIVATE KEY-----", "")
                    .replaceAll("-----END RSA PRIVATE KEY-----", "")
                    .replaceAll("-----BEGIN PRIVATE KEY-----", "")
                    .replaceAll("-----END PRIVATE KEY-----", "");

            publicKeyContent = publicKeyContent.replaceAll("\\r|\\n", "").replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "");

            System.out.println("--------------privateKey:-------------- ");
            System.out.println(privateKeyContent);

            System.out.println("--------------publicKey:-------------- ");
            System.out.println(publicKeyContent);

            String signx2 = RSASign(plainText, getPrivateKey(privateKeyContent));
            System.out.println("RSA signx2:" + signx2);

            boolean verify2 = RSAVerify(plainText, "tc/G2bkONMmJPUWO+pARIArW+WWGnrkTjf3yVnSslvisDCuVH3Irvx/c3tWUTKfoCCCKxGbWwX0gqnvaudr/pfSsoIsvlnLbGvKdeqerPuBeyPfNz7JuqOz+Qp2PtZyJ4BraQAM14tmSlOUoO946hewatZYTscW1qwJ6pzgjOeGaO8HWMbTy1veAHBvoDdO1bzIz09/kMFjrXxl3lu8A0CzkbkTjNO+ACqRfu9hxkX18k4DNRzvFxyxNzyOjU+LGfqp26qq2FpqNWaAhu8pAlZs+V3NouWAA8V38pF8RJu3neAHcwKpdjr+0N5eX3y+Ey1h9Us+IxzdM1FBMvfBEFg==", getPublicKey(publicKeyContent));
            System.out.println("RSAVerify:" + verify2);

        } catch (NoSuchAlgorithmException e) {
            System.err.println(e.getMessage());
        }

    }
}
