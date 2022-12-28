package ru.domesticroots.webview;

import androidx.annotation.AnyThread;
import androidx.annotation.NonNull;

import java.util.Set;
import java.util.concurrent.ConcurrentSkipListSet;

@AnyThread
class CertificateCheckCache {

    @NonNull
    private final Set<String> cacheWithSuccessfulChecks = new ConcurrentSkipListSet<>();

    @NonNull
    private final Set<String> cacheWithFailedChecks = new ConcurrentSkipListSet<>();

    CertificateCheckCache(){}

    void addSuccessful(@NonNull String url) {
        cacheWithSuccessfulChecks.add(url);
    }

    void addFailed(@NonNull String url) {
        cacheWithFailedChecks.add(url);
    }

    boolean containsSuccessful(@NonNull String url) {
        return cacheWithSuccessfulChecks.contains(url);
    }

    boolean containsFailed(@NonNull String url) {
        return cacheWithFailedChecks.contains(url);
    }

}
