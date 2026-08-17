// Perfil de alvo dos grupos de ataque: quais setores e quais países/regiões o
// grupo ataca. O actors.json (MITRE + MISP) não traz esses campos — só a
// descrição em prosa —, então eles são derivados dela uma vez, no load.
//
// ponytail: derivação por palavra-chave sobre a descrição. Erra em texto
// ambíguo; se algum dia existir um feed com vitimologia estruturada (ETDA,
// MISP `victim` galaxy), troque a derivação pelo campo real.
import { SECTOR_RULES, compileLabelMap, matchLabels } from './ctiIntel.js';

// Só conta o que aparece numa frase sobre vitimologia. Sem isso "China-based
// group" faria a China virar alvo, e "government-backed" faria Governo virar
// setor atacado.
const VICTIM_CUE = /\b(target|targets|targeted|targeting|victim|victims|attack|attacks|attacked|campaign|campaigns|compromise|compromised|compromising|intrusion|intrusions|breach|breached|espionage|operations?|focus|focused|against|entities|organizations|organisations|companies|sectors?|industr\w+)\b/i;

// Países e regiões que aparecem como alvo em relatórios de CTI. Rótulo → termos.
export const TARGET_REGIONS = {
    'United States': ['united states', 'u.s.', 'us government', 'american'],
    Canada: ['canada', 'canadian'],
    Mexico: ['mexico', 'mexican'],
    Brazil: ['brazil', 'brazilian'],
    'Latin America': ['latin america', 'south america', 'central america'],
    'United Kingdom': ['united kingdom', 'u.k.', 'britain', 'british'],
    Germany: ['germany', 'german'],
    France: ['france', 'french'],
    Spain: ['spain', 'spanish'],
    Italy: ['italy', 'italian'],
    Poland: ['poland', 'polish'],
    Netherlands: ['netherlands', 'dutch'],
    Europe: ['europe', 'european', 'nato'],
    Ukraine: ['ukraine', 'ukrainian'],
    Russia: ['russia', 'russian'],
    Belarus: ['belarus', 'belarusian'],
    Turkey: ['turkey', 'turkish'],
    Israel: ['israel', 'israeli'],
    'Saudi Arabia': ['saudi arabia', 'saudi'],
    'United Arab Emirates': ['united arab emirates', 'uae', 'emirati'],
    Qatar: ['qatar', 'qatari'],
    Iran: ['iran', 'iranian'],
    Iraq: ['iraq', 'iraqi'],
    Syria: ['syria', 'syrian'],
    Lebanon: ['lebanon', 'lebanese'],
    'Middle East': ['middle east', 'middle eastern', 'gulf states'],
    Egypt: ['egypt', 'egyptian'],
    Africa: ['africa', 'african', 'sub-saharan'],
    'South Africa': ['south africa', 'south african'],
    India: ['india', 'indian'],
    Pakistan: ['pakistan', 'pakistani'],
    Afghanistan: ['afghanistan', 'afghan'],
    China: ['china', 'chinese'],
    Taiwan: ['taiwan', 'taiwanese'],
    'Hong Kong': ['hong kong'],
    Japan: ['japan', 'japanese'],
    'South Korea': ['south korea', 'south korean', 'republic of korea'],
    'North Korea': ['north korea', 'north korean'],
    Mongolia: ['mongolia', 'mongolian'],
    Vietnam: ['vietnam', 'vietnamese'],
    Thailand: ['thailand', 'thai'],
    Philippines: ['philippines', 'filipino'],
    Indonesia: ['indonesia', 'indonesian'],
    Malaysia: ['malaysia', 'malaysian'],
    Singapore: ['singapore'],
    'Southeast Asia': ['southeast asia', 'south-east asia', 'south east asia'],
    Australia: ['australia', 'australian'],
    'New Zealand': ['new zealand'],
    Global: ['worldwide', 'globally', 'global campaign', 'multiple countries', 'around the world'],
};

const REGION_RULES = compileLabelMap(TARGET_REGIONS);

/** Frases da descrição que falam de vítima/alvo — o resto é ruído de atribuição. */
const victimText = (description) => String(description || '')
    .split(/(?<=[.;!?])\s+/)
    .filter((sentence) => VICTIM_CUE.test(sentence))
    .join(' ');

/**
 * Setores e regiões que o grupo ataca, derivados da descrição.
 * `ownCountry` sai da lista de alvos: o país de origem é atribuição, não vítima.
 */
export function actorTargeting({ description, country } = {}) {
    const text = victimText(description);
    if (!text) return { sectors: [], targets: [] };
    const own = String(country || '').trim().toLowerCase();
    return {
        sectors: matchLabels(text, SECTOR_RULES),
        targets: matchLabels(text, REGION_RULES).filter((label) => label.toLowerCase() !== own),
    };
}

export const TARGET_REGION_LABELS = Object.keys(TARGET_REGIONS);
