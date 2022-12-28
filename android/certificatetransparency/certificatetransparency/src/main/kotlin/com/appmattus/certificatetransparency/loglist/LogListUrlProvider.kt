package com.appmattus.certificatetransparency.loglist

interface LogListUrlProvider {
    val logListUrl: String
    val logListSignatureUrl: String?
}

class GstaticLogListUrlProvider : LogListUrlProvider {
    private val baseUrl = "https://www.gstatic.com/ct/log_list/v2/"

    override val logListUrl: String = baseUrl + "log_list.json"
    override val logListSignatureUrl: String = baseUrl + "log_list.sig"
}
