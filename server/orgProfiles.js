// Perfil da organização: o contexto que o app usa para calibrar o que mostra.
//
// Setores e regiões usam exatamente os rótulos que o resto do app já produz —
// SECTOR_RULES em ctiIntel.js carimba `item.sectors` em cada notícia, e
// TARGET_REGIONS em actorProfile.js deriva `actor.targets` de cada ator. Um
// vocabulário próprio aqui exigiria duas tabelas de tradução envelhecendo em
// paralelo, e o join com atores e notícias deixaria de ser de graça.
import crypto from 'crypto';
import { SECTOR_RULES } from './ctiIntel.js';
import { TARGET_REGION_LABELS } from './actorProfile.js';
// As marcas do perfil são os termos que a vigilância de phishing procura no
// urlscan, então quem valida é o módulo que faz a busca — validar em dois
// lugares é ter duas regras discordando daqui a três meses.
import { normalizeBrands } from './phishingWatch.js';

export const ORG_LIMITS = {
    profilesPerUser: 10,
    nameLength: 80,
    assets: 100,
    assetFieldLength: 60,
    minAssetTerm: 3,
    otList: 30,
    otFieldLength: 40,
    actors: 50,
};

export const ORG_SECTORS = SECTOR_RULES.map((rule) => rule.label);
export const ORG_REGIONS = [...TARGET_REGION_LABELS];

export const createOrgError = (status, publicMessage) =>
    Object.assign(new Error(publicMessage), { status, publicMessage });

const CONTROL_CHARS = /[\x00-\x1F\x7F]/g;
const cleanText = (value, max) =>
    String(value ?? '').replace(CONTROL_CHARS, ' ').replace(/\s+/g, ' ').trim().slice(0, max);

const newId = () => `org_${crypto.randomBytes(8).toString('hex')}`;

const fromVocabulary = (values, vocabulary, field) => {
    const out = [];
    for (const raw of Array.isArray(values) ? values : []) {
        const value = cleanText(raw, ORG_LIMITS.nameLength);
        if (!value) continue;
        if (!vocabulary.includes(value)) throw createOrgError(400, `${field} inválido: ${value}`);
        if (!out.includes(value)) out.push(value);
    }
    return out;
};

const normalizeAssets = (values) => {
    const list = Array.isArray(values) ? values : [];
    if (list.length > ORG_LIMITS.assets) throw createOrgError(400, `no máximo ${ORG_LIMITS.assets} ativos por perfil`);
    const out = [];
    const seen = new Set();
    for (const raw of list) {
        const vendor = cleanText(raw?.vendor, ORG_LIMITS.assetFieldLength);
        const product = cleanText(raw?.product, ORG_LIMITS.assetFieldLength);
        if (!vendor && !product) continue;
        for (const term of [vendor, product]) {
            if (term && term.replace(/[^a-z0-9]/gi, '').length < ORG_LIMITS.minAssetTerm) {
                throw createOrgError(400, `ativo curto demais: ${term}`);
            }
        }
        const key = `${vendor.toLowerCase()}|${product.toLowerCase()}`;
        if (seen.has(key)) continue;
        seen.add(key);
        out.push({ vendor, product });
    }
    return out;
};

const normalizeOt = (value) => {
    const source = value && typeof value === 'object' ? value : {};
    const list = (items) => {
        const arr = Array.isArray(items) ? items : [];
        if (arr.length > ORG_LIMITS.otList) throw createOrgError(400, `no máximo ${ORG_LIMITS.otList} itens em OT`);
        const out = [];
        for (const raw of arr) {
            const item = cleanText(raw, ORG_LIMITS.otFieldLength);
            if (item && !out.includes(item)) out.push(item);
        }
        return out;
    };
    return { present: Boolean(source.present), vendors: list(source.vendors), protocols: list(source.protocols) };
};

/**
 * Valida e normaliza o que o cliente mandou salvar.
 *
 * `knownActorIds` é um Set opcional: quando vem, ids fora do catálogo são
 * rejeitados. Fica como parâmetro para a função continuar pura — quem tem o
 * catálogo é a rota, não este módulo.
 */
export function normalizeProfileInput(input = {}, existing = null, now = new Date().toISOString(), owner = {}, knownActorIds = null) {
    const pick = (key) => (input[key] !== undefined ? input[key] : existing?.[key]);

    const name = cleanText(pick('name'), ORG_LIMITS.nameLength);
    if (!name) throw createOrgError(400, 'nome do perfil é obrigatório');

    const rawActors = Array.isArray(pick('actors')) ? pick('actors') : [];
    if (rawActors.length > ORG_LIMITS.actors) throw createOrgError(400, `no máximo ${ORG_LIMITS.actors} atores fixados`);
    const actors = [];
    for (const raw of rawActors) {
        const id = cleanText(raw, ORG_LIMITS.nameLength);
        if (!id || actors.includes(id)) continue;
        if (knownActorIds && !knownActorIds.has(id)) throw createOrgError(400, `ator desconhecido: ${id}`);
        actors.push(id);
    }

    return {
        id: existing?.id || newId(),
        ownerId: existing?.ownerId || owner.sub,
        ownerLogin: existing?.ownerLogin || owner.login,
        name,
        sectors: fromVocabulary(pick('sectors'), ORG_SECTORS, 'setor'),
        regions: fromVocabulary(pick('regions'), ORG_REGIONS, 'região'),
        assets: normalizeAssets(pick('assets')),
        brands: normalizeBrands(pick('brands')),
        ot: normalizeOt(pick('ot')),
        actors,
        createdAt: existing?.createdAt || now,
        updatedAt: now,
    };
}

// fs entra por injeção para os testes nunca tocarem o arquivo real. Arquivo
// corrompido ou ausente é store vazio: configurar é acessório, e uma falha aqui
// não pode derrubar o servidor inteiro.
export function createProfileStore({ filePath, readFileSync, writeJsonAtomic }) {
    let profiles = [];
    try {
        const parsed = JSON.parse(readFileSync(filePath, 'utf8'));
        profiles = Array.isArray(parsed) ? parsed.filter((p) => p && p.id && p.ownerId) : [];
    } catch { /* store vazio */ }

    // Grava antes de avançar a memória: se writeJsonAtomic estourar (disco
    // cheio, EACCES), a memória não pode ficar à frente do que está no disco.
    const commit = (next) => { writeJsonAtomic(filePath, next); profiles = next; };
    const mine = (ownerId) => profiles.filter((profile) => profile.ownerId === ownerId);

    return {
        list(ownerId) {
            return mine(ownerId).sort((a, b) => String(a.name).localeCompare(String(b.name)));
        },
        // Sem dono: é o agendador da vigilância de phishing varrendo todo mundo.
        // Nenhuma rota devolve isto — quem responde ao navegador usa list/get.
        allProfiles() { return [...profiles]; },
        // 404 e não 403: confirmar que o id existe já entregaria informação do
        // perfil de outro dono.
        get(ownerId, id) {
            const found = profiles.find((profile) => profile.id === id && profile.ownerId === ownerId);
            if (!found) throw createOrgError(404, 'perfil não encontrado');
            return found;
        },
        create(owner, input, now = new Date().toISOString(), knownActorIds = null) {
            if (mine(owner.sub).length >= ORG_LIMITS.profilesPerUser) {
                throw createOrgError(409, `limite de ${ORG_LIMITS.profilesPerUser} perfis atingido`);
            }
            const profile = normalizeProfileInput(input, null, now, owner, knownActorIds);
            commit([...profiles, profile]);
            return profile;
        },
        update(ownerId, id, input, now = new Date().toISOString(), knownActorIds = null) {
            const current = profiles.find((profile) => profile.id === id && profile.ownerId === ownerId);
            if (!current) throw createOrgError(404, 'perfil não encontrado');
            const next = normalizeProfileInput(input, current, now, { sub: ownerId, login: current.ownerLogin }, knownActorIds);
            commit(profiles.map((profile) => (profile.id === id ? next : profile)));
            return next;
        },
        remove(ownerId, id) {
            const next = profiles.filter((profile) => !(profile.id === id && profile.ownerId === ownerId));
            if (next.length === profiles.length) return false;
            commit(next);
            return true;
        },
    };
}
