package com.surveysampling.libs.webpush

import groovyx.net.http.*
import org.bouncycastle.jce.*
import org.bouncycastle.jce.spec.*
import org.bouncycastle.util.BigIntegers

import javax.crypto.*
import javax.crypto.spec.*
import java.nio.ByteBuffer
import java.security.*
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.*
/**
 * Created by SSI.
 */
public class Encryptor {
    private static BigInteger g512 = new BigInteger("1234567890", 16);
    public static final int GCM_TAG_LENGTH = 16; // in bytes
    private static BigInteger p512 = new BigInteger("1234567890", 16);

    public static void main(String[] args) throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

     //   https://updates.push.services.mozilla.com/wpush/v2/gAAAAABYZuDgoMub3OPSivN1pKLjnArk6RNcw9N-tgAGVX3ljVd_u3dXZbHHxv8tDEFiQgbeU8teVd7JHpNPHyuRLXrFbv7A8cOmt0BBHI1rsZfpPN78mJ20VAjLOcl6ed7ZUn5Kz9mwC68s-dQuCdQ-OY9KgmzPxeaIFM3VH69NxHwG0IYQutQ","keys":{"auth":"yPvyQWVemNle-SAYdomx6Q","p256dh":"BFPZ7Srtojcluj10f8mnEySX5rS6fLAfY8A-TPG6R3uoJtfwpoaRAS7vhdXH5q6w3M0k6CXV0wXw60KkdG01mQs
//        String subscriptionUrl = "https://updates.push.services.mozilla.com/wpush/v2/gAAAAABYZuDgoMub3OPSivN1pKLjnArk6RNcw9N-tgAGVX3ljVd_u3dXZbHHxv8tDEFiQgbeU8teVd7JHpNPHyuRLXrFbv7A8cOmt0BBHI1rsZfpPN78mJ20VAjLOcl6ed7ZUn5Kz9mwC68s-dQuCdQ-OY9KgmzPxeaIFM3VH69NxHwG0IYQutQ";
//        byte[] clientPublicKeyRaw = Base64.getUrlDecoder().decode("BFPZ7Srtojcluj10f8mnEySX5rS6fLAfY8A-TPG6R3uoJtfwpoaRAS7vhdXH5q6w3M0k6CXV0wXw60KkdG01mQs")
//        byte[] clientAuthSecretRaw = Base64.getUrlDecoder().decode("yPvyQWVemNle-SAYdomx6Q")

        String saltStr = 'Odp85FO6m8ZxVv6UES5nbg=='
        String subscriptionUrl = "https://fcm.googleapis.com/fcm/send/crV61jgsNBY:APA91bEdPY7uQdWVzPjdU2wor5CrlPiOmkZai5XcD1pvUpDFsgs3uvR0LA2pjpLjsoN__j5-ch1tyIYoWYggEL-wBOVVr8JsdoF_yuh5jOp-7XeyucHE_XHA3-wPXi1r9o-W4pZU-x9s";
        byte[] clientPublicKeyRaw = Base64.getUrlDecoder().decode("BNDfSPDWTn9cv08ca-ea4qm0IuYEW_pCorhhCABqEhBMV6HPgLqajtXfqKKv1VRQWo_0F1dmR8E2Y9AY1629o34=");
        byte[] clientAuthSecretRaw = Base64.getUrlDecoder().decode("1Pc3Dhp7hTy_1hPbAYY1dA==");

//        byte[] salt = new byte[16];
//        new SecureRandom().nextBytes(salt);

    //    println "salt" +  Base64.urlEncoder.encodeToString(salt)

        byte[] salt = Base64.urlDecoder.decode(saltStr)
        ECPublicKey clientPublicKey = (ECPublicKey) getPublicKeyFrom(clientPublicKeyRaw);

//        KeyPairGenerator serverKeyGen = KeyPairGenerator.getInstance("EC", "BC");
//        serverKeyGen.initialize(new ECGenParameterSpec("prime256v1"), new SecureRandom());
//        KeyPair serverKeyPair = serverKeyGen.generateKeyPair();
//        ECPublicKey serverPublicKey = (ECPublicKey)serverKeyPair.getPublic();

        ECPublicKey serverPublicKey = getPublicKeyFrom(Base64.urlDecoder.decode('BMW-_0TeYxK7JvIg3PvyMN9fSlpunKhZ-veZxnbe41KkbSOi8nPZ5NR74xvWkCRlUOpXoiZO7p2fVM19mjmYnMs='))
        ECPrivateKey serverPrivateKey = getPrivateKeyFrom(Base64.urlDecoder.decode('Eql2xtHYQHVFKOe9BjNTid7gYjumQZOmQa191y-m9uo='))
        KeyPair serverKeyPair = new KeyPair(serverPublicKey, serverPrivateKey)

        println "public key" + Base64.encoder.encodeToString(getRawBytes(serverPublicKey))
        println "privatek key" + Base64.encoder.encodeToString(BigIntegers.asUnsignedByteArray(serverKeyPair.private.s))


        KeyAgreement serverKeyAgree = KeyAgreement.getInstance("ECDH", "BC");
        serverKeyAgree.init(serverKeyPair.getPrivate());
        serverKeyAgree.doPhase(clientPublicKey, true);

        byte[] secret = serverKeyAgree.generateSecret();

        def clientInfo = "Content-Encoding: auth\0".getBytes("UTF-8")
        println "ikm " +  Base64.urlEncoder.encodeToString(clientInfo)
        byte[] prk = createDerivedKey(clientAuthSecretRaw, secret, 32, clientInfo);
        println "prk: " + Base64.urlEncoder.encodeToString(prk)

        byte[] contentEncryptionKeyInfo = createInfo("aesgcm", clientPublicKey, serverPublicKey);
        byte[] contentEncryptionKey = createDerivedKey(salt, prk, 16, contentEncryptionKeyInfo);
        println "content info " + Base64.urlEncoder.encodeToString(contentEncryptionKeyInfo)
        println "content encryption key " + Base64.urlEncoder.encodeToString(contentEncryptionKey)

        byte[] nonceInfo = createInfo("nonce", clientPublicKey, serverPublicKey);
        byte[] nonce = createDerivedKey(salt, prk, 12, nonceInfo);
        println "nonce info " + Base64.urlEncoder.encodeToString(nonceInfo)
        println "nonce " + Base64.urlEncoder.encodeToString(nonce)

        Key key = new SecretKeySpec(contentEncryptionKey, "AES");

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        GCMParameterSpec spec = new GCMParameterSpec(16 * 8, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        cipher.update([(byte) 0,     (byte) 0].toArray(new byte[0]))
       // cipher.update("Hello, world!".getBytes("UTF-8"));
        byte[] encryptedMessage = cipher.doFinal("Hello, world!".getBytes("UTF-8"));

        println "cipher " +  Base64.urlEncoder.encodeToString(encryptedMessage)

        RESTClient restClient = new RESTClient(subscriptionUrl);

        KeyPair vapidKeys = JwtWebPushBuilder.getVAPIDKeys();
        ECPrivateKey privateKey = vapidKeys.private

        println "PUBLIC SERVER KEY IS" + Base64.urlEncoder.withoutPadding().encodeToString(getRawBytes(vapidKeys.public));

        println "private key is" + Base64.getUrlEncoder().withoutPadding().encodeToString(getPrivateRawBytes(privateKey))

        def resp = restClient.post(
                headers: [
                        'TTL' : 100,
                        'Authorization': JwtWebPushBuilder.buildJwTToken(vapidKeys, 'https://fcm.googleapis.com'), //'WebPush eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJodHRwczovL2ZjbS5nb29nbGVhcGlzLmNvbSIsImV4cCI6MTQ4MzQzMzQzOCwic3ViIjoibWFpbHRvOnBhdWxzaWRlbGVhdUBnbWFpbC5jb20ifQ.AUDWND8MulshGGoGzBo5iBtn-x-9xxD8zEO0Q5BN-btshmSnpYbx-Lp8saNK2zhjAljpAx6aIk5XlWfag_sUUw',
                        'Encryption': "salt=" + Base64.getUrlEncoder().withoutPadding().encodeToString(salt),
                        'Crypto-Key': "dh=" + Base64.getUrlEncoder().withoutPadding().encodeToString(getRawBytes(serverPublicKey)) + ';' +
                                    'p256ecdsa=' + Base64.getUrlEncoder().withoutPadding().encodeToString(getRawBytes(vapidKeys.public)),
                        'Content-Encoding': 'aesgcm',
                        'Content-Type': 'application/octet-stream'
                ],
                body: encryptedMessage,
               requestContentType: ContentType.BINARY
        )
        println resp.data
    }

    public static byte[] getRawBytes(ECPublicKey publicKey) {
        ECPoint clientPublicW = publicKey.getW();

        ByteBuffer byteBuffer = ByteBuffer.allocate(65);
        byteBuffer.put((byte) 4);
        byteBuffer.put(BigIntegers.asUnsignedByteArray(clientPublicW.getAffineX()));
        byteBuffer.put(BigIntegers.asUnsignedByteArray(clientPublicW.getAffineY()));

        String google = "RzGaur_gPZH74hof4wRDzYpT1qEzj_8ReNH8kf8TaZs"
        byte[] googleb = Base64.urlDecoder.decode(google)
        return byteBuffer.array();
    }

    public static byte[] getPrivateRawBytes(ECPrivateKey privateKey) {
        byte[] s = BigIntegers.asUnsignedByteArray(privateKey.s)
        return s
    }

    public static PublicKey getPublicKeyFrom(byte[] p256EllipticCurvePoint) throws Exception {
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("prime256v1");
        KeyFactory kf = KeyFactory.getInstance("ECDSA", "BC");
        ECNamedCurveSpec params = new ECNamedCurveSpec("prime256v1", spec.getCurve(), spec.getG(), spec.getN());
        ECPoint pubPoint =  ECPointUtil.decodePoint(params.getCurve(), p256EllipticCurvePoint);
        java.security.spec.ECPublicKeySpec pubKeySpec = new java.security.spec.ECPublicKeySpec(pubPoint, params);
        return kf.generatePublic(pubKeySpec);
    }

    public static PrivateKey getPrivateKeyFrom(byte[] p256EllipticCurvePoint) throws Exception {
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("prime256v1");
        KeyFactory kf = KeyFactory.getInstance("ECDSA", "BC");
        ECNamedCurveSpec params = new ECNamedCurveSpec("prime256v1", spec.getCurve(), spec.getG(), spec.getN());
        java.security.spec.ECPrivateKeySpec privateKeySpec = new java.security.spec.ECPrivateKeySpec(BigIntegers.fromUnsignedByteArray(p256EllipticCurvePoint), params)
        return kf.generatePrivate(privateKeySpec)
    }



    public static byte[] createDerivedKey(byte[] inputSalt, byte[] inputKeyMaterial, int size, byte[] info)
            throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException {

        if (size > 32) {
            throw new Exception('Cannot return keys of more than 32 bytes, ${length} requested');
        }

        // Extract
        Mac keyHmac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secret_key = new SecretKeySpec(inputSalt, "HmacSHA256");
        keyHmac.init(secret_key);
        keyHmac.update(inputKeyMaterial)
        byte[] key = keyHmac.doFinal()

        // Expand
        Mac infoHmac = Mac.getInstance("HmacSHA256");
        infoHmac.init(new SecretKeySpec(key, "HmacSHA256"))
        infoHmac.update(info);
        infoHmac.update((byte) 1)

        return Arrays.copyOf(infoHmac.doFinal(), size)
//        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
//
//        ByteBuffer infoBuffer = ByteBuffer.allocate(info.length + 1);
//        infoBuffer.put(info);
//        infoBuffer.put((byte) 1);
//        hkdf.init(new HKDFParameters(inputKeyMaterial, inputSalt, infoBuffer.array()));
//
//        byte[] derivedKey = new byte[size];
//        hkdf.generateBytes(derivedKey, 0, derivedKey.length);
//
//        return derivedKey;
       // return new SecretKeySpec(derivedKey, "sha256");
   }

    public static byte[] createInfo(String type, ECPublicKey clientPublicKey, ECPublicKey serverPublicKey) throws Exception {

        // The start index for each element within the buffer is:
        // value               | length | start    |
        // -----------------------------------------
        // 'Content-Encoding: '| 18     | 0        |
        // type                | len    | 18       |
        // nul byte            | 1      | 18 + len |
        // 'P-256'             | 5      | 19 + len |
        // nul byte            | 1      | 24 + len |
        // client key length   | 2      | 25 + len |
        // client key          | 65     | 27 + len |
        // server key length   | 2      | 92 + len |
        // server key          | 65     | 94 + len |
        // For the purposes of push encryption the length of the keys will
        // always be 65 bytes.

        byte[] typeAsBytes = type.getBytes("UTF-8");
        ByteBuffer info = ByteBuffer.allocate(18 + typeAsBytes.length + 1 + 5 + 1 + 2 + 65 + 2 + 65);
        info.put("Content-Encoding: ".getBytes("UTF-8"));
        info.put(typeAsBytes);
        info.put((byte) 0);
        info.put("P-256".getBytes("UTF-8"));
        info.put((byte) 0);
        info.putShort((short)65);
        info.put(getRawBytes(clientPublicKey));
        info.putShort((short)65);
        info.put(getRawBytes(serverPublicKey));

        return info.array();
    }

}
