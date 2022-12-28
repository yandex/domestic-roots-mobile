package ru.domesticroots.webview;

import android.content.Context;
import android.net.http.SslError;
import androidx.annotation.AnyThread;
import androidx.annotation.MainThread;
import androidx.annotation.NonNull;

@AnyThread
public interface WebViewSslErrorHandler {

    boolean handleSslError(@NonNull SslError error,
                           @NonNull Callback callback);

    @NonNull
    static WebViewSslErrorHandler create(@NonNull Context context,
                                         @NonNull CertificatesProvider certificatesProvider,
                                         @NonNull CTLogDataSource ctLogDataSource) {
        return new WebViewSslErrorHandlerImpl(context.getApplicationContext(), certificatesProvider, ctLogDataSource, Logger.EMPTY);
    }

    @NonNull
    static WebViewSslErrorHandler create(@NonNull Context context,
                                         @NonNull CertificatesProvider certificatesProvider,
                                         @NonNull CTLogDataSource ctLogDataSource,
                                         @NonNull Logger logger) {
        return new WebViewSslErrorHandlerImpl(context.getApplicationContext(), certificatesProvider, ctLogDataSource, logger);
    }

    @MainThread
    interface Callback {
        void onProceeded();
        void onCanceled();
    }

}
