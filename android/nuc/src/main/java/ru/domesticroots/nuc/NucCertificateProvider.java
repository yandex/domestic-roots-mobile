package ru.domesticroots.nuc;

import ru.domesticroots.webview.CertificatesProvider;
import ru.domesticroots.webview.IoUtils;

import android.content.Context;

import androidx.annotation.NonNull;

import java.io.IOException;
import java.io.InputStream;

public class NucCertificateProvider implements CertificatesProvider {
    @NonNull
    private final Context context;

    public NucCertificateProvider(@NonNull Context context) {
        this.context = context.getApplicationContext();
    }

    @NonNull
    @Override
    public byte[][] provide() {
        InputStream rawData = context.getResources().openRawResource(R.raw.nuc_cert);
        try {
            byte[] bytes = IoUtils.inputStreamToByteArray(rawData);
            return new byte[][] { bytes };
        } catch (IOException e) {
            throw new RuntimeException("Failed to get certificate from resources", e);
        }
    }
}
