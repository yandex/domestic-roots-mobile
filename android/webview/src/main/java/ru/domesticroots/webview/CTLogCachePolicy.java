package ru.domesticroots.webview;

import java.util.Date;

public interface CTLogCachePolicy {

    boolean isExpired(Date lastWriteDate, Date currentDate);

}
