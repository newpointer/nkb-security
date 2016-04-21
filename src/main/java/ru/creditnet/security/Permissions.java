package ru.creditnet.security;

/**
 * @author Alexander Yastrebov
 */
public enum Permissions {

    DATA_VIEWFULL,
    //
    SEARCH,
    SEARCH_RELATED,
    SEARCH_TRACES,
    //
    REPORT_LIST,
    REPORT_VIEW,
    REPORT_SAVE,
    REPORT_DELETE,
    REPORT_EXPORT_IMAGE,
    REPORT_EXPORT_DOCX,
    REPORT_EXPORT_PDF,
    //
    REQUEST_EGRUL_COMPANY,
    REQUEST_EGRUL_INDIVIDUAL_FOUNDER,
    REQUEST_EGRUL_INDIVIDUAL_EXECUTIVE;

    public static String[] stringValues() {
        Permissions[] values = values();
        String[] result = new String[values.length];
        for (int i = 0; i < values.length; i++) {
            result[i] = values[i].name();
        }
        return result;
    }
}
