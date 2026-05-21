import axios from 'axios';

const token = "censys_XyCrQmfx_Mk2ByqnKmrHEoWH2MeeSMH26";
const domain = "google.com";

axios.get(`https://api.platform.censys.io/v3/global/asset/domain/${domain}`, {
    headers: {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/json'
    }
})
.then(res => {
    console.log("Domain lookup Success!");
    console.log("Data keys:", Object.keys(res.data));
})
.catch(err => {
    console.error("Domain lookup Error! Code:", err.response?.status);
    console.error("Error data:", err.response?.data);
});
