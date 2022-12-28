package ru.domesticroots.webview;

import androidx.annotation.AnyThread;
import androidx.annotation.NonNull;

public interface CertificatesProvider {

    @NonNull
    @AnyThread
    byte[][] provide();
}
