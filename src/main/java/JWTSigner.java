import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.crypto.bc.BouncyCastleFIPSProviderSingleton;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;


public class JWTSigner {

    public JWTSigner() {

    }

    // Get RSA keys. Uses key size of 2048.
    public static Map<String, Object> getRSAKeys() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        Map<String, Object> keys = new HashMap<String, Object>();
        keys.put("private", privateKey);
        keys.put("public", publicKey);
        return keys;
    }

    public void signJWT(PrivateKey privateKey, RSAPublicKey publicKey) throws JOSEException {

        //Approach 1:
        JWSSigner signer = new RSASSASigner(privateKey);
        signer.getJCAContext().setProvider(BouncyCastleFIPSProviderSingleton.getInstance());

        // Prepare JWT with claims set
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("poc")
                .issuer("https://abc.com")
                .expirationTime(new Date(new Date().getTime() + 60 * 1000))
                .claim("acquirer_response_code","00")
                .claim("initiator_trace_id","281")
                .build();

        JWSObject jwsObject = new JWSObject(
                new JWSHeader.Builder(JWSAlgorithm.PS256).build(),
                claimsSet.toPayload());

        jwsObject.sign(signer);


        // Create RSA verifier and set BC FIPS provider
        JWSVerifier verifier = new RSASSAVerifier(publicKey);
        verifier.getJCAContext().setProvider(BouncyCastleFIPSProviderSingleton.getInstance());

        jwsObject.verify(verifier);

        System.out.println("JWT Signed! - "+ jwsObject.verify(verifier) +" " + jwsObject.serialize());

        //*********************//

        //Approach 2:
        // RSA signatures require a public and private RSA key pair, the public key
        // must be made known to the JWS recipient in order to verify the signatures
        RSAKey rsaJWK = new RSAKeyGenerator(2048)
                .keyID(UUID.randomUUID().toString())
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.PS256)
                .generate();

        RSAKey rsaPublicJWK = rsaJWK.toPublicJWK();
        PublicKey publicKey1 = rsaJWK.toPublicKey();
        RSAPublicKey rsaPublicKey = rsaJWK.toRSAPublicKey();
        PrivateKey privateKey1 = rsaJWK.toPrivateKey();
        RSAPrivateKey rsaPrivateKey = rsaJWK.toRSAPrivateKey();

        System.out.println("rsaPublicJWK : " + rsaPublicJWK);
        System.out.println("publicKey1 : " + publicKey1);
        System.out.println("rsaPublicKey : " + rsaPublicKey);
        System.out.println("privateKey1 : " + privateKey1);
        System.out.println("rsaPrivateKey : " + rsaPrivateKey);

        // Create RSA-signer with the private key
        JWSSigner signer1 = new RSASSASigner(rsaJWK);
        signer.getJCAContext().setProvider(BouncyCastleFIPSProviderSingleton.getInstance());

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.PS256).keyID(rsaJWK.getKeyID()).jwk(rsaPublicJWK).build(),
                claimsSet);

        // Compute the RSA signature
        signedJWT.sign(signer1);

        // To serialize to compact form, produces something like
        // eyJhbGciOiJSUzI1NiJ9.SW4gUlNBIHdlIHRydXN0IQ.IRMQENi4nJyp4er2L
        // mZq3ivwoAjqa1uUkSBKFIX7ATndFF5ivnt-m8uApHO4kfIFOrW7w2Ezmlg3Qd
        // maXlS9DhN0nUk_hGI3amEjkKd0BWYCB8vfUbUv0XGjQip78AI4z1PrFRNidm7
        // -jPDm5Iq0SZnjKjCNS5Q15fokXZc8u0A
        String s = signedJWT.serialize();

        System.out.println(s);


    }
}
