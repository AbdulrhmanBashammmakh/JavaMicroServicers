package org.app.mutualAuthOne;

import lombok.SneakyThrows;

import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.util.Date;
import java.util.Set;

//KeystoreGenerator
public class TruststoreLoader {


public void getLoad() throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException {
// Load the server's certificate.
    FileInputStream fis = new FileInputStream("server.crt");
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    X509Certificate serverCert = (X509Certificate) cf.generateCertificate(fis);
    fis.close();

    // Create a truststore for the client.
    KeyStore ks = KeyStore.getInstance("JKS");
    ks.load(null, null);

    // Import the server's certificate into the truststore.
    ks.setCertificateEntry("server", serverCert);

    // Save the truststore.
    ks.store(new FileOutputStream("client.jks"), "password".toCharArray());
}

public void get() throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
    // Generate a keystore for the server.
    KeyStore ks = KeyStore.getInstance("JKS");
    char[] password = "password".toCharArray();
    ks.load(null, password);

    // Generate a self-signed certificate for the server.
    X509Certificate serverCert = generateSelfSignedCertificate(ks, "server", password,"");

    // Save the keystore.
    ks.store(new FileOutputStream("server.jks"), password);

    // Generate a truststore for the client.
    ks = KeyStore.getInstance("JKS");
    ks.load(null, null);

    // Import the server's certificate into the truststore.
    ks.setCertificateEntry("server", serverCert);

    // Save the truststore.
    ks.store(new FileOutputStream("client.jks"), password);
}

    private static X509Certificate generateSelfSignedCertificate(KeyStore ks, String alias, char[] password,String name) throws CertificateException, NoSuchAlgorithmException, KeyStoreException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(new byte[0]));
        X509Certificate x509Certificate = new X509Certificate() {


            @Override
            public boolean hasUnsupportedCriticalExtension() {
                return false;
            }

            @Override
            public Set<String> getCriticalExtensionOIDs() {
                return null;
            }

            @Override
            public Set<String> getNonCriticalExtensionOIDs() {
                return null;
            }

            @Override
            public byte[] getExtensionValue(String oid) {
                return new byte[0];
            }

            @Override
            public byte[] getEncoded() throws CertificateEncodingException {
                return new byte[0];
            }

            @Override
            public void verify(PublicKey key) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {

            }

            @Override
            public void verify(PublicKey key, String sigProvider) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {

            }

            @Override
            public String toString() {
                return null;
            }

            @Override
            public PublicKey getPublicKey() {
                return null;
            }

            @Override
            public void checkValidity() throws CertificateExpiredException, CertificateNotYetValidException {

            }

            @Override
            public void checkValidity(Date date) throws CertificateExpiredException, CertificateNotYetValidException {

            }

            @Override
            public int getVersion() {
                return 0;
            }

            @Override
            public BigInteger getSerialNumber() {
                return BigInteger.ONE;
            }

            @Override
            public Principal getIssuerDN() {
                return new X500Principal("CN="+name);
            }

            @Override
            public Principal getSubjectDN() {
                return new X500Principal("CN="+name);
            }

            @Override
            public Date getNotBefore() {
                return new Date();
            }

            @Override
            public Date getNotAfter() {
                return new Date(System.currentTimeMillis() + (1000 * 60 * 60 * 24 * 365));
            }

            @Override
            public byte[] getTBSCertificate() throws CertificateEncodingException {
                return new byte[0];
            }

            @SneakyThrows
            @Override
            public byte[] getSignature() {
                return ks.getCertificate(alias).getPublicKey().getEncoded();
            }

            @Override
            public String getSigAlgName() {
                return alias;
            }

            @Override
            public String getSigAlgOID() {
                return "SHA256WithRSA";
            }

            @Override
            public byte[] getSigAlgParams() {
                return new byte[0];
            }

            @Override
            public boolean[] getIssuerUniqueID() {
                return new boolean[0];
            }

            @Override
            public boolean[] getSubjectUniqueID() {
                return new boolean[0];
            }

            @Override
            public boolean[] getKeyUsage() {
                return new boolean[0];
            }

            @Override
            public int getBasicConstraints() {
                return 0;
            }


        };

        ks.setCertificateEntry(alias, cert);
        return cert;
    }
}
