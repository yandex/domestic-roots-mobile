package ru.domesticroots.webview;

import androidx.annotation.AnyThread;
import androidx.annotation.NonNull;

import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;

@AnyThread
class CertificateCheckCache {

    @NonNull
    private final Set<X509Certificate> cacheWithSuccessfulChecks = new HashSet<>();

    @NonNull
    private final Set<X509Certificate> cacheWithFailedChecks = new HashSet<>();

    CertificateCheckCache(){}

    synchronized void addSuccessful(@NonNull X509Certificate certificate) {
        cacheWithSuccessfulChecks.add(certificate);
    }

    synchronized void addFailed(@NonNull X509Certificate certificate) {
        cacheWithFailedChecks.add(certificate);
    }

    synchronized boolean containsSuccessful(@NonNull X509Certificate certificate) {
        return cacheWithSuccessfulChecks.contains(certificate);
    }

    synchronized boolean containsFailed(@NonNull X509Certificate certificate) {
        return cacheWithFailedChecks.contains(certificate);
    }

}
