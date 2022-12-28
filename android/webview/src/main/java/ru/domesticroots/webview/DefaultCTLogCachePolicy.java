package ru.domesticroots.webview;

import java.util.Calendar;
import java.util.Date;

public class DefaultCTLogCachePolicy implements CTLogCachePolicy {

    @Override
    public boolean isExpired(Date lastWriteDate, Date currentDate) {
        Calendar expiryCalendar = Calendar.getInstance();
        expiryCalendar.setTime(lastWriteDate);
        expiryCalendar.add(Calendar.DAY_OF_MONTH, 1);
        return currentDate.after(expiryCalendar.getTime());
    }
}
