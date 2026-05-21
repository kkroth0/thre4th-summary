import axios from 'axios';

const token = "censys_XyCrQmfx_Mk2ByqnKmrHEoWH2MeeSMH26";
const ip = "8.8.8.8";
const url = `https://api.platform.censys.io/v3/global/asset/host/${ip}`;

axios.get(url, {
    headers: {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/json'
    }
})
.then(res => {
    const services = res.data.result.resource.services;
    if (services && services.length > 0) {
        console.log("First service:", JSON.stringify(services[0], null, 2));
    }
})
.catch(err => {
    console.error("Error:", err.message);
});
