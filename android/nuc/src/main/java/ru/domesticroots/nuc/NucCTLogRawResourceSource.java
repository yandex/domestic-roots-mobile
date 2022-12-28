package ru.domesticroots.nuc;

import android.content.Context;
import androidx.annotation.NonNull;
import ru.domesticroots.webview.CTLogRawResourceSource;

public class NucCTLogRawResourceSource extends CTLogRawResourceSource {
    public NucCTLogRawResourceSource(@NonNull Context context) {
        super(context, R.raw.nuc_ctlog);
    }
}
