package ru.domesticroots.webview;

import android.content.Context;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.RawRes;

import java.io.IOException;
import java.io.InputStream;

public class CTLogRawResourceSource implements CTLogDataSource {
    @NonNull
    private final Context context;
    @RawRes
    private final int rawResId;

    public CTLogRawResourceSource(@NonNull Context context,
                                  int rawResId) {
        this.context = context.getApplicationContext();
        this.rawResId = rawResId;
    }

    @NonNull
    @Override
    public byte[] getRawLog() {
        InputStream rawData = context.getResources().openRawResource(rawResId);
        try {
            return IoUtils.inputStreamToByteArray(rawData);
        } catch (IOException e) {
            throw new RuntimeException("Failed to get certificate from resources", e);
        }
    }

    @Nullable
    @Override
    public CTLogCachePolicy getCachePolicy() {
        return null;
    }
}
