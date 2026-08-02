const HEARTH_REPO = 'https://github.com/THORCollective/HEARTH/blob/main/';

const clean = (value, max = 2000) => String(value ?? '').trim().slice(0, max);
const list = (value, max = 100) => [...new Set(
    (Array.isArray(value) ? value : []).map((item) => clean(item, 120)).filter(Boolean),
)].slice(0, max);

/** Converte o `const HUNTS_DATA = [...]` publicado pelo HEARTH em JSON seguro. */
export function parseHearthData(source) {
    try {
        const text = String(source ?? '');
        const start = text.indexOf('[');
        const end = text.lastIndexOf(']');
        if (start < 0 || end <= start) throw new Error('missing array');
        const raw = JSON.parse(text.slice(start, end + 1));
        if (!Array.isArray(raw)) throw new Error('not an array');

        return raw
            .filter((hunt) => hunt && hunt.id && hunt.title)
            .map((hunt) => ({
                id: clean(hunt.id, 40),
                origin: 'hearth',
                category: clean(hunt.category, 40),
                title: clean(hunt.title, 2000),
                tactics: list(Array.isArray(hunt.tactic) ? hunt.tactic : clean(hunt.tactic).split(',')),
                techniques: list(hunt.techniques).map((id) => id.toUpperCase()),
                tags: list(hunt.tags),
                submitter: {
                    name: clean(hunt.submitter?.name, 160),
                    link: clean(hunt.submitter?.link, 1000),
                },
                notes: clean(hunt.notes, 5000),
                why: clean(hunt.why, 10000),
                references: clean(hunt.references, 10000),
                status: clean(hunt.status, 40),
                created: clean(hunt.created, 60),
                sourceUrl: hunt.file_path ? `${HEARTH_REPO}${clean(hunt.file_path, 500)}` : '',
            }));
    } catch {
        throw new Error('catálogo HEARTH inválido');
    }
}
