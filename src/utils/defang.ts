// Defang / refang helpers for safely displaying and sharing IOCs.
// "Defanging" neutralises an indicator so it can't be accidentally clicked or
// auto-linked (http -> hxxp, "." -> "[.]"), the convention SOC analysts use in
// tickets, SIEM queries and reports.

// Defang a single IOC (URL, domain, IP or email host).
export const defang = (ioc: string): string =>
    ioc
        .replace(/^https?:\/\//i, (m) => m.replace(/t/gi, "x")) // http(s) -> hxxp(s)
        .replace(/\./g, "[.]")
        .replace(/@/g, "[@]");

// Reverse a defanged IOC back to its live form.
export const refang = (ioc: string): string =>
    ioc
        .replace(/\[\.\]/g, ".")
        .replace(/\[@\]|\[at\]/gi, "@")
        .replace(/\[:\]/g, ":")
        .replace(/hxx(ps?)/gi, "htt$1");

// Defang a list and join with newlines — ready for clipboard / file output.
export const defangList = (iocs: string[]): string => iocs.map(defang).join("\n");
