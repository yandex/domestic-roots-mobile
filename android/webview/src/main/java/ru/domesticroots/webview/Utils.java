package ru.domesticroots.webview;

import android.annotation.SuppressLint;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

public class Utils {
    private Utils() {}

    @NonNull
    public static X509Certificate[] getX509Chain(@NonNull Certificate[] chain) {
        X509Certificate[] x509Chain = new X509Certificate[chain.length];
        for (int i = 0; i < chain.length; i++) {
            Certificate partOfChain = chain[i];
            x509Chain[i] = (X509Certificate) partOfChain;
        }
        return x509Chain;
    }

    @Nullable
    public static X509TrustManager getTrustManagerWithCertificates(
            @NonNull byte[][] certificatesBytes,
            @NonNull Logger logger
    ) {
        KeyStore keyStore;
        try {
            keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null);
        } catch (GeneralSecurityException | IOException e) {
            logger.e("Failed to create KeyStore", e);
            return null;
        }

        for (int i = 0; i < certificatesBytes.length; i++) {
            byte[] encoded = certificatesBytes[i];
            X509Certificate certificate;
            try {
                certificate = extractCertificateFromBytes(encoded);
            } catch (CertificateException e) {
                logger.e("Failed to extract certificate from bytes", e);
                continue;
            }
            try {
                keyStore.setCertificateEntry("custom_cert_" + i, certificate);
            } catch (KeyStoreException e) {
                logger.e("Failed to store certificate in custom KeyStore", e);
            }
        }

        try {
            return createTrustManager(keyStore, logger);
        } catch (KeyStoreException | NoSuchAlgorithmException e) {
            logger.e("Failed to create TrustManager", e);
            return null;
        }
    }

    @NonNull
    public static X509Certificate extractCertificateFromBytes(@NonNull byte[] encoded)
            throws CertificateException {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        Certificate certificate = certificateFactory.generateCertificate(
                new ByteArrayInputStream(encoded));
        if (!(certificate instanceof X509Certificate)) {
            throw new CertificateException(String.format(
                    "Generated certificate is %s, but expected X509Certificate", certificate.getClass()));
        }
        return (X509Certificate) certificate;
    }

    @Nullable
    public static X509TrustManager createTrustManager(@NonNull KeyStore keyStore,
                                                      @NonNull Logger logger)
            throws KeyStoreException, NoSuchAlgorithmException {
        String algorithm = TrustManagerFactory.getDefaultAlgorithm();
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(algorithm);
        tmf.init(keyStore);

        TrustManager[] trustManagers;
        try {
            trustManagers = tmf.getTrustManagers();
        } catch (RuntimeException e) {
            logger.e("TrustManagerFactory.getTrustManagers() unexpectedly threw: %s", e);
            throw new KeyStoreException(e);
        }

        for (TrustManager tm : trustManagers) {
            if (tm instanceof X509TrustManager) {
                try {
                    return (X509TrustManager) tm;
                } catch (IllegalArgumentException e) {
                    String className = tm.getClass().getName();
                    logger.e("Error creating trust manager (" + className + "): " + e);
                }
            }
        }
        logger.e("Could not find suitable trust manager");
        return null;
    }

    @NonNull
    public static SSLSocketFactory getTrustAllSocketFactory() {
        return getSSLSocketFactory(getTrustAllCertsManager());
    }

    @NonNull
    @SuppressLint({"CustomX509TrustManager", "TrustAllX509TrustManager"})
    private static TrustManager[] getTrustAllCertsManager() {
        return new TrustManager[] {
                new X509TrustManager() {
                    @Override
                    public void checkClientTrusted(X509Certificate[] chain, String authType) {
                    }

                    @Override
                    public void checkServerTrusted(X509Certificate[] chain, String authType) {
                    }

                    @Override
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[]{};
                    }
                }
        };
    }

    @NonNull
    private static SSLSocketFactory getSSLSocketFactory(@NonNull TrustManager[] trustManagers) {
        try {
            final SSLContext sslContext = SSLContext.getInstance("SSL");
            sslContext.init(null, trustManagers, new SecureRandom());
            return sslContext.getSocketFactory();
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            throw new RuntimeException(e);
        }
    }

}
