// O ThreatFox busca por curinga quando `exact_match` não vai no corpo: procurar
// 1.1.1.1 devolve também 11.1.1.100. Numa planilha de atribuição isso cola um
// grupo no indicador errado.
//
// Trocar a busca para exata resolveria o falso positivo mas custaria recall: o
// ThreatFox guarda C2 como `ip:porta` e guarda URL inteira, então a busca exata
// pelo IP ou pelo domínio puro deixaria de casar com o que interessa. Por isso o
// curinga fica e a resposta é filtrada aqui, exigindo que a consulta apareça
// como componente inteiro do IOC — nunca como pedaço de um número maior.

const HOST_PORT = /^(.+):(\d{1,5})$/;

export function acceptedThreatFoxResponse(response) {
    if (response.data?.query_status === 'illegal_search_term') throw Object.assign(new Error('ThreatFox rejected this search term'), { code: 'PROVIDER_QUERY_UNSUPPORTED', response: { status: 422, data: response.data } });
    return response;
}

const hostOf = (value) => {
    try {
        return new URL(value).hostname.toLowerCase().replace(/^\[|\]$/g, '');
    } catch {
        return '';
    }
};

const bare = (value) => {
    const text = String(value || '').trim().toLowerCase();
    const withPort = HOST_PORT.exec(text);
    return withPort ? withPort[1] : text;
};

export const iocMatchesQuery = (ioc, query) => {
    const value = String(ioc || '').trim().toLowerCase();
    const term = String(query || '').trim().toLowerCase();
    if (!value || !term) return false;
    if (value === term) return true;
    // `1.1.1.1:443` casa a consulta pelo IP; `11.1.1.100` não casa `1.1.1.1`.
    if (bare(value) === term) return true;
    // IOC é a URL e a consulta é o host dela (ou o contrário).
    if (hostOf(value) === term) return true;
    if (hostOf(term) === value) return true;
    return false;
};

export const filterExactIocs = (payload, query) => {
    if (!payload || payload.query_status !== 'ok' || !Array.isArray(payload.data)) return payload;
    return { ...payload, data: payload.data.filter((entry) => iocMatchesQuery(entry?.ioc, query)) };
};
