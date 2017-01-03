package com.surveysampling.libs.webpush

import io.jsonwebtoken.*
import io.jsonwebtoken.impl.crypto.EllipticCurveProvider
import org.bouncycastle.asn1.sec.SECNamedCurves
import org.bouncycastle.asn1.x9.X9ECParameters
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.util.io.pem.PemObject
import org.bouncycastle.util.io.pem.PemWriter

import java.nio.ByteBuffer
import java.security.*
import java.security.interfaces.*
import java.security.spec.*
import java.time.Instant
import java.time.temporal.ChronoUnit
/**
 * Created by SSI.
 */
class JwtWebPushBuilder {
    private static final X9ECParameters curve = SECNamedCurves.getByName ("secp256R1");
    private static final ECDomainParameters domain = new ECDomainParameters (curve.getCurve (), curve.getG (), curve.getN (), curve.getH ());


    public static void storeKeyPair() {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        KeyPairGenerator kpg;
        kpg = KeyPairGenerator.getInstance("EC","BC");

        ECGenParameterSpec ecsp;
        ecsp = new ECGenParameterSpec("prime256v1");
        kpg.initialize(ecsp);

        KeyPair kp = kpg.genKeyPair();
        ECPrivateKey privKey = kp.getPrivate();
        ECPublicKey pubKey = kp.getPublic();


        println privKey.s
        println privKey.getEncoded()
        println pubKey.getEncoded()

        String google = "BBkT0NcVmfctqSlquU3rmAfK6hop0oUnalRDADQnvBEOpfQF9nQeONNezWnsRwxntoMycKRCHJsatNqmZLhv3Qw";
        String locale = "BP6340KYUI_vlqmvCsxIdQIhN-yWEZuJYdYlRfAMwqijFv4DO5B7Eqcnwuy_HRGvbmu2GVW80NCZmpgRVbidaMM=";

        println Base64.urlEncoder.encodeToString(Encryptor.getRawBytes(pubKey))
    }


    public static final byte[] private_key = [48, -127, -109, 2, 1, 0, 48, 19, 6, 7, 42, -122, 72, -50, 61, 2, 1, 6, 8,
                                              42, -122, 72, -50, 61, 3, 1, 7, 4, 121, 48, 119, 2, 1, 1, 4, 32, 71, 8,
                                              80, 18, 114, 122, -69, 101, -95, 114, -30, -78, 24, -14, -57, -67, 98,
                                              122, -103, -34, -92, 55, 72, -63, 64, 54, 76, -58, 12, -72, 121, -1, -96,
                                              10, 6, 8, 42, -122, 72, -50, 61, 3, 1, 7, -95, 68, 3, 66, 0, 4, -2, -73,
                                              -29, 66, -104, 80, -113, -17, -106, -87, -81, 10, -52, 72, 117, 2, 33,
                                              55, -20, -106, 17, -101, -119, 97, -42, 37, 69, -16, 12, -62, -88, -93,
                                              22, -2, 3, 59, -112, 123, 18, -89, 39, -62, -20, -65, 29, 17, -81, 110,
                                              107, -74, 25, 85, -68, -48, -48, -103, -102, -104, 17, 85, -72, -99,
                                              104, -61]

    public static final byte[] public_key = [48, 89, 48, 19, 6, 7, 42, -122, 72, -50, 61,
                                             2, 1, 6, 8, 42, -122, 72, -50, 61, 3, 1, 7, 3, 66,
                                             0, 4, -2, -73, -29, 66, -104, 80, -113, -17, -106, -87, -81, 10, -52, 72,
                                             117, 2, 33, 55, -20, -106, 17, -101, -119, 97, -42, 37, 69, -16, 12, -62,
                                             -88, -93, 22, -2, 3, 59, -112, 123, 18, -89, 39, -62, -20, -65, 29, 17,
                                             -81, 110, 107, -74, 25, 85, -68, -48, -48, -103, -102, -104, 17, 85,
                                             -72, -99, 104, -61]


    public static KeyPair getVAPIDKeys() {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        KeyFactory kf = KeyFactory.getInstance("EC"); // or "EC" or whatever
        PrivateKey privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(private_key));
        PublicKey publicKey = kf.generatePublic(new X509EncodedKeySpec(public_key));

        StringWriter stringWriter = new StringWriter()
        PemWriter pemWriter = new PemWriter(stringWriter)
        pemWriter.writeObject(new PemObject("ECDSA", publicKey.encoded))
        pemWriter.close()

        println "PUBLIC KEY IN PEM FORMAT" + Base64.encoder.encodeToString(publicKey.encoded)
        return new KeyPair(publicKey, privateKey);
    }

    public static String buildJwTToken(KeyPair keyPair, String origin) {
        String google = "BBkT0NcVmfctqSlquU3rmAfK6hop0oUnalRDADQnvBEOpfQF9nQeONNezWnsRwxntoMycKRCHJsatNqmZLhv3Qw";
        String locale = "BP6340KYUI_vlqmvCsxIdQIhN-yWEZuJYdYlRfAMwqijFv4DO5B7Eqcnwuy_HRGvbmu2GVW80NCZmpgRVbidaMM=";

        byte[] googleBytes = Base64.urlDecoder.decode(google)
        byte[] localeBytes = Base64.urlDecoder.decode(locale)
        def instant = Instant.now().plus(12, ChronoUnit.HOURS)


        println System.currentTimeMillis()
        println Instant.now().epochSecond
        println Instant.now().epochSecond
        println ("new data date is" + Date.from(Instant.now().plus(12, ChronoUnit.HOURS)))
        println "current date" + instant;

        Base64.Encoder encoder = Base64.urlEncoder.withoutPadding()
        println "The date is " + instant

        def header = new groovy.json.JsonBuilder()
        header typ: "JWT", alg: 'ES256'

        println "header is: " + header.toString()
        String headerEncoded = encoder.encodeToString(header.toString().getBytes("UTF-8"))

        def body = new groovy.json.JsonBuilder()
                             //1483435107
        body aud: origin, exp: Math.floor(Date.from(instant).time / 1000), sub: "mailto:paulsideleau@gmail.com"

        // node.js {"aud":"https://fcm.googleapis.com","exp":1483435107,"sub":"mailto:paulsideleau@gmail.com"}
        //eyJhdWQiOiJodHRwczovL2ZjbS5nb29nbGVhcGlzLmNvbSIsImV4cCI6MTQ4MzQzNTEwNywic3ViIjoibWFpbHRvOnBhdWxzaWRlbGVhdUBnbWFpbC5jb20ifQ
        println "body is: " + body.toString()
        String bodyEncoded = encoder.encodeToString(body.toString().getBytes("UTF-8"))
       // assert bodyEncoded == 'eyJhdWQiOiJodHRwczovL2ZjbS5nb29nbGVhcGlzLmNvbSIsImV4cCI6MTQ4MzQzNTEwNywic3ViIjoibWFpbHRvOnBhdWxzaWRlbGVhdUBnbWFpbC5jb20ifQ'
        String headerAndBody = "$headerEncoded.$bodyEncoded"

        Signature signature = Signature.getInstance("SHA256withECDSA", "BC")
        signature.initSign(keyPair.private)
        signature.update(headerAndBody.getBytes('UTF-8'))
        byte[] signed = signature.sign()


        int rLength = signed[3]
        def rList = signed.toList().subList(4, 4 + rLength)
        def sList = signed.toList().subList(4 + rLength + 2, signed.length)
        byte[] r = rList.size() == 33 ? rList.subList(1, 33).toArray(new byte[0]) : rList.toArray(new byte[0])
        byte[] s = sList.size() == 33 ? sList.subList(1, 33).toArray(new byte[0]) : sList.toArray(new byte[0])

        signature.initVerify(keyPair.public)
        signature.update(headerAndBody.getBytes('UTF-8'))
        println "signed=" + signature.verify(signed)

        def rawSignature = EllipticCurveProvider.transcodeSignatureToConcat(signed, 64)
        ByteBuffer buffer = ByteBuffer.allocate(64)
        buffer.put(rawSignature);

        String signatureEncoded = encoder.encodeToString(buffer.array())
        println "Signature encoded with frameworked " + signatureEncoded
        String signature2 = "T22-KV8_MH3kxb2UNN8FscoQsJ4Rsr93d8qFxvpCMzrCDXrYvbPUilW0yTRxkFMjItxRJl85KKwoXZ63pXuS3g"

//        ECDSASigner signer = new ECDSASigner (new HMacDSAKCalculator (new SHA256Digest ()));
//        ECPrivateKey privateKey = keyPair.private
//        signer.init (true, new ECPrivateKeyParameters (privateKey.s, domain));
//        def signatures = signer.generateSignature (headerAndBody.getBytes('UTF-8'));
//
//        byte[] unsignedByteR = BigIntegers.asUnsignedByteArray(signatures[0])
//        byte[] unsignedByteS = BigIntegers.asUnsignedByteArray(signatures[1])

        buffer = ByteBuffer.allocate(64)
        buffer.put(r)
        buffer.put(s)

       signatureEncoded = encoder.encodeToString(buffer.array())

        println "Signature my way" + signatureEncoded
        println "Signature base64 " + Base64.encoder.encodeToString(buffer.array())

        String jwt = "$headerAndBody.$signatureEncoded"
        String googleJwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJodHRwczovL2ZjbS5nb29nbGVhcGlzLmNvbSIsImV4cCI6MTQ4MzQzNDU4NCwic3ViIjoibWFpbHRvOnBhdWxzaWRlbGVhdUBnbWFpbC5jb20ifQ.jfhWw924iyhXafvj2q1wglOAEAjIcHfV-LLCJq-SOtuhlu945eFhttlrCTo-mctQHGHR5LOHgIo0wt2PMGC5qQ"

//        Jwts.parser().setSigningKey(keyPair.public).parse(jwt)
        println jwt
        return "WebPush " + jwt;
    }

    public static String buildJwTTokenOld(KeyPair keyPair, String origin) {
        def date = Date.from(Instant.now().plus(12, ChronoUnit.HOURS))
        println "The date is " + date
        String compactJws = Jwts.builder()
                .setHeaderParam("typ", "JWT")
                .setClaims(aud: origin, exp: date.time, sub: "mailto:paulsideleau@gmail.com")
        // .setExpiration(date)
                .signWith(SignatureAlgorithm.ES256, keyPair.getPrivate())
                .compact();

        println compactJws;

        def jwt = Jwts.parser().
                setSigningKey(keyPair.public)
                .parse(compactJws)
        println jwt.body
        println jwt.header.toString()
        println Base64.urlEncoder.encodeToString(Encryptor.getRawBytes(keyPair.public))
        def header = new groovy.json.JsonBuilder()
        header typ: "JWT", alg: "ES256"

        return "WebPush " + compactJws;
    }
    /**
     * https://developers.google.com/web/updates/2016/07/web-push-interop-wins
     * @param args
     * @throws Exception
     */
    public static void main(String[] args) throws Exception {
      // storeKeyPair();

        KeyPair keyPair = getVAPIDKeys()
        buildJwTToken(keyPair, 'test')

//        String encodedHeader = Base64.urlEncoder.encode(header.toString().getBytes('UTF-8'));
//
//       // ZonedDateTime.now().plusHours(24).withZoneSameInstant(ZoneOffset.UTC)
//        def payload = new groovy.json.JsonBuilder()
//        payload aud: origin, exp: 86400, sub: "mailto: test@test.com"
//        String encodedPayload = Base64.urlEncoder.encode(payload.toString().getBytes('UTF-8'));



        /*
        byte[] privateKeyBytes;
byte[] publicKeyBytes;
KeyFactory kf = KeyFactory.getInstance("RSA"); // or "EC" or whatever
PrivateKey privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
PublicKey publicKey = kf.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
         */
    }
}
