import https from 'https';
import fs from 'fs';

https.get('https://cve.circl.lu/api/last', (res) => {
    let data = '';
    res.on('data', chunk => { data += chunk; });
    res.on('end', () => {
        try {
            const list = JSON.parse(data);
            const excerpt = JSON.stringify(list.slice(0, 2), null, 2);
            fs.writeFileSync('scratch/cve_sample.json', excerpt);
            console.log("Successfully wrote sample!");
        } catch (e) {
            console.log("Raw length:", data.length);
            fs.writeFileSync('scratch/cve_sample.json', data.substring(0, 20000));
            console.log("Wrote raw substring due to parse error:", e.message);
        }
    });
});
