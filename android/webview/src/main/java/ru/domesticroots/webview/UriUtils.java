package ru.domesticroots.webview;

import android.net.Uri;

import androidx.annotation.NonNull;

public class UriUtils {

    @NonNull
    public static String remotePathAndParams(@NonNull String url) {
        return Uri.parse(url)
                .buildUpon()
                .clearQuery()
                .path("/")
                .toString();
    }

}
