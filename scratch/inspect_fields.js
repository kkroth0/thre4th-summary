import https from 'https';

https.get('https://cve.circl.lu/api/last', (res) => {
    let data = '';
    res.on('data', chunk => { data += chunk; });
    res.on('end', () => {
        try {
            const list = JSON.parse(data);
            if (!Array.isArray(list) || list.length === 0) {
                console.log("Empty or not array:", typeof list);
                return;
            }
            const item = list[0];
            console.log("Document Tracking ID:", item.document?.tracking?.id);
            console.log("Document Tracking Date:", item.document?.tracking?.initial_release_date || item.document?.tracking?.current_release_date);
            console.log("Document Title:", item.document?.title);
            console.log("Document Publisher Name:", item.document?.publisher?.name);
            console.log("Notes Categories:", item.document?.notes?.map(n => n.category));
            console.log("Notes Excerpt:", item.document?.notes?.map(n => `[${n.category}]: ${n.text ? n.text.substring(0, 100) : ''}`));
            
            console.log("\nVulnerabilities Count:", item.vulnerabilities?.length);
            if (item.vulnerabilities && item.vulnerabilities.length > 0) {
                const vuln = item.vulnerabilities[0];
                console.log("Vulnerability keys:", Object.keys(vuln));
                console.log("Vulnerability CVE:", vuln.cve);
                console.log("Vulnerability Title:", vuln.title);
                console.log("Vulnerability Scores:", JSON.stringify(vuln.scores, null, 2));
            }
        } catch (e) {
            console.error("Parse error:", e.message);
        }
    });
});
