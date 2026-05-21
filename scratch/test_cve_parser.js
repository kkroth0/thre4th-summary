import axios from 'axios';

async function test() {
    try {
        console.log("Fetching live data from CIRCL...");
        const response = await axios.get('https://cve.circl.lu/api/last', { timeout: 8000 });
        console.log("Response status:", response.status);
        console.log("Is array?", Array.isArray(response.data));
        
        if (Array.isArray(response.data)) {
            const formatted = [];
            response.data.forEach((item, index) => {
                // If it is the old flat format
                if (item.id) {
                    formatted.push({
                        id: item.id,
                        cvss: item.cvss,
                        summary: item.summary,
                        Published: item.Published,
                        Modified: item.Modified
                    });
                    return;
                }
                
                // If it is the new CSAF format
                const document = item.document || {};
                const tracking = document.tracking || {};
                const docId = tracking.id || 'Unknown-Advisory';
                const docTitle = document.title || '';
                
                const summaryNote = document.notes?.find(n => n.category === 'summary' || n.category === 'general');
                const docSummary = summaryNote ? summaryNote.text : (document.title || 'No summary available.');
                const publishedDate = tracking.initial_release_date || tracking.current_release_date || new Date().toISOString();
                
                if (item.vulnerabilities && item.vulnerabilities.length > 0) {
                    item.vulnerabilities.forEach(vuln => {
                        const cveId = vuln.cve || docId;
                        
                        let cvss = null;
                        if (vuln.scores && vuln.scores.length > 0) {
                            const scoreObj = vuln.scores[0];
                            cvss = scoreObj.cvss_v3?.baseScore || scoreObj.cvss_v2?.baseScore || null;
                        }
                        
                        const vulnNote = vuln.notes?.find(n => n.category === 'summary' || n.category === 'general');
                        const summaryText = vulnNote ? vulnNote.text : (vuln.title || docSummary);
                        
                        formatted.push({
                            id: cveId,
                            cvss: cvss,
                            summary: summaryText,
                            Published: publishedDate,
                            Modified: tracking.current_release_date || publishedDate
                        });
                    });
                } else {
                    formatted.push({
                        id: docId,
                        cvss: null,
                        summary: docSummary,
                        Published: publishedDate,
                        Modified: tracking.current_release_date || publishedDate
                    });
                }
            });

            console.log(`Parsed ${formatted.length} CVE items.`);
            console.log("\nSample parsed items (first 3):");
            console.log(JSON.stringify(formatted.slice(0, 3), null, 2));
        }
    } catch (e) {
        console.error("Test execution failed:", e.message);
    }
}

test();
