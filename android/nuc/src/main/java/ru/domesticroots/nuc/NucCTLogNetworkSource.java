package ru.domesticroots.nuc;

import ru.domesticroots.webview.CTLogNetworkSource;

public class NucCTLogNetworkSource extends CTLogNetworkSource {
    public NucCTLogNetworkSource() {
        super("https://browser-resources.s3.yandex.net/ctlog/ctlog.json");
    }
}
