# ThreatSumm4ry 🛡️

> **Comprehensive Threat Intelligence Dashboard** - Aggregate security analysis from 23+ threat intelligence vendors in one unified interface.

## 🛠️ Installation

```bash
# Clone the repository
git clone <YOUR_GIT_URL>
cd intel-vista-22

# Install dependencies
npm install

# Copy environment example
cp .env.example .env

# Add your API keys to .env (optional)
# Edit .env and add your keys
```

## 🔑 Environment Variables

Create a `.env` file in the root directory:

```env
# Free APIs (No keys needed - leave empty)
# IP Geolocation, WHOIS, AlienVault OTX, URLhaus, ThreatFox, 
# MalwareBazaar, PhishStats, Ransomware.live, CIRCL, PhishTank, 
# Pulsedive, ThreatCrowd

# Premium APIs (Add your keys)
VITE_VIRUSTOTAL_API_KEY=your_key_here
VITE_ABUSEIPDB_API_KEY=your_key_here
VITE_SHODAN_API_KEY=your_key_here

VITE_HYBRID_ANALYSIS_API_KEY=your_key_here
VITE_CRIMINALIP_API_KEY=your_key_here
VITE_METADEFENDER_API_KEY=your_key_here
```

## 📦 Tech Stack

- **Frontend Framework:** React 18
- **Build Tool:** Vite 5
- **Language:** TypeScript
- **Styling:** Tailwind CSS
- **UI Components:** shadcn/ui
- **State Management:** TanStack Query (React Query)
- **Icons:** Lucide React

## 🚢 Deployment

See [DEPLOYMENT.md](./DEPLOYMENT.md) for detailed deployment instructions.

### Quick Deploy Options:

**Vercel (Recommended):**
```bash
npm install -g vercel
npm run build
vercel --prod
```

**Netlify:**
```bash
npm install -g netlify-cli
netlify deploy --prod --dir=dist
```

**Docker:**
```bash
docker build -t threatsumm4ry .
docker run -d -p 8080:80 threatsumm4ry
```
## 📚 Documentation

- [DEPLOYMENT.md](./DEPLOYMENT.md) - Comprehensive deployment guide
- [API_RESOURCES.md](./API_RESOURCES.md) - API vendor documentation
- [.env.example](./.env.example) - Environment variable template

