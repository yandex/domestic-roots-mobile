package ru.domesticroots.webview;

import android.content.Context;
import android.net.http.SslError;
import android.os.AsyncTask;
import androidx.annotation.NonNull;

public class WebViewSslErrorHandlerImpl implements WebViewSslErrorHandler {

    @NonNull
    private final Context context;
    @NonNull
    private final CertificatesProvider certificatesProvider;
    @NonNull
    private final CTLogDataSource ctLogDataSource;
    @NonNull
    private final Logger logger;
    @NonNull
    private final CertificateCheckCache certificateCheckCache = new CertificateCheckCache();

    public WebViewSslErrorHandlerImpl(@NonNull Context context,
                                      @NonNull CertificatesProvider certificatesProvider,
                                      @NonNull CTLogDataSource ctLogDataSource,
                                      @NonNull Logger logger) {
        this.context = context;
        this.certificatesProvider = certificatesProvider;
        this.ctLogDataSource = ctLogDataSource;
        this.logger = logger;
    }

    @Override
    public boolean handleSslError(@NonNull SslError error, @NonNull Callback callback) {
        if (error.getPrimaryError() != SslError.SSL_UNTRUSTED) {
            return false;
        }
        String url = UriUtils.remotePathAndParams(error.getUrl());

        downloadAndCheckServerCertificates(url, error, certificatesProvider.provide(),
                ctLogDataSource, callback, certificateCheckCache, logger);
        return true;
    }

    private void downloadAndCheckServerCertificates(
            @NonNull String url,
            @NonNull SslError sslError,
            @NonNull byte[][] certificates,
            @NonNull CTLogDataSource ctLogDataSource,
            @NonNull Callback callback,
            @NonNull CertificateCheckCache certificateCheckCache,
            @NonNull Logger logger
    ) {
        new DownloadCertsAndCheckTask(context,
                sslError,
                url,
                certificates,
                ctLogDataSource,
                certificateCheckCache,
                callback,
                logger
        ).executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR);
    }
}
