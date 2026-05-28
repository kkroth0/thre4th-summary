const fs = require('fs');

let code = fs.readFileSync('server/index.js', 'utf8');

// 1. Remove requireAuth from route definitions
code = code.replace(/, requireAuth,/g, ',');
code = code.replace(/, requireAuth \(/g, ' (');

// 2. Remove configuration block
const configStart = code.indexOf('// Session and Auth Configuration');
const configEnd = code.indexOf('// Token utilities');
if (configStart !== -1 && configEnd !== -1) {
    code = code.substring(0, configStart) + code.substring(configEnd);
}

// 3. Remove Token utilities
const utilsStart = code.indexOf('// Token utilities');
const utilsEnd = code.indexOf('// CORS Config');
if (utilsStart !== -1 && utilsEnd !== -1) {
    code = code.substring(0, utilsStart) + code.substring(utilsEnd);
}

// 4. Remove requireAuth middleware
const mwStart = code.indexOf('// Auth middleware');
const mwEnd = code.indexOf('// Helper to extract quota info');
if (mwStart !== -1 && mwEnd !== -1) {
    code = code.substring(0, mwStart) + code.substring(mwEnd);
}

// 5. Remove Auth endpoints
const endpointsStart = code.indexOf('// --- Authentication Endpoints ---');
const endpointsEnd = code.indexOf('// Latest CVEs from CIRCL');
if (endpointsStart !== -1 && endpointsEnd !== -1) {
    code = code.substring(0, endpointsStart) + code.substring(endpointsEnd);
}

fs.writeFileSync('server/index.js', code);
console.log("Successfully removed auth from server/index.js");
