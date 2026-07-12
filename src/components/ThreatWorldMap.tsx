import { useEffect, useMemo, useState } from "react";
import { ComposableMap, Geographies, Geography, Marker } from "react-simple-maps";
import { geoEqualEarth, type GeoProjection } from "d3-geo";
import { feature } from "topojson-client";
import type { Feature, FeatureCollection, Geometry } from "geojson";

const W = 980;
const H = 500;

// Fixed dark "cyber map" palette (independent of the app light/dark theme) so
// the beams and victim nodes always read with high contrast.
const COUNTRY_FILL = "#16223a";
const COUNTRY_STROKE = "#2c4066";
const BEAM = "#fb7185"; // rose — reads as "attack/ransomware"
const BEAM_DOT = "#ffe4e6";
const VICTIM = "#fb7185";
const HUB = "#fbbf24"; // amber origin hubs

// ISO-3166 alpha-2 → [lon, lat] approximate country centroids, covering the
// countries our ransomware feed surfaces (plus common extras).
const COUNTRY_COORDS: Record<string, [number, number]> = {
  US: [-98, 39], CA: [-106, 56], MX: [-102, 23], BR: [-51, -10], AR: [-64, -34],
  CL: [-71, -35], CO: [-74, 4], PE: [-75, -9], UY: [-56, -33], EC: [-78, -1],
  BO: [-64, -17], CR: [-84, 10], CU: [-79, 22], DO: [-70, 19], GT: [-90, 15],
  HN: [-86, 15], NI: [-85, 13], PA: [-80, 9], PR: [-66, 18], PY: [-58, -23],
  SV: [-89, 14], VE: [-66, 7],
  GB: [-2, 54], IE: [-8, 53], FR: [2, 46], ES: [-4, 40], PT: [-8, 39],
  IT: [12, 42], DE: [10, 51], NL: [5, 52], BE: [4, 50], CH: [8, 47],
  AT: [14, 47], PL: [19, 52], CZ: [15, 50], SK: [19, 48], HU: [19, 47],
  RO: [25, 46], BG: [25, 43], GR: [22, 39], SE: [15, 62], NO: [10, 62],
  FI: [26, 64], DK: [10, 56], UA: [31, 49], RU: [90, 62], TR: [35, 39],
  BY: [28, 53], RS: [21, 44], HR: [16, 45],
  ZA: [24, -29], EG: [30, 27], NG: [8, 10], GH: [-1, 8], KE: [38, 0],
  MA: [-6, 32], DZ: [3, 28], TN: [9, 34], AO: [18, -12], ET: [40, 8],
  IN: [79, 22], CN: [104, 35], JP: [138, 36], KR: [128, 36], TW: [121, 24],
  HK: [114, 22], SG: [104, 1], ID: [113, -2], MY: [102, 4], TH: [101, 15],
  VN: [106, 16], PH: [122, 13], PK: [70, 30], BD: [90, 24], SA: [45, 24],
  AE: [54, 24], IL: [35, 31], QA: [51, 25], KW: [48, 29], IR: [53, 32],
  AU: [134, -25], NZ: [172, -42],
};

// Symbolic ransomware "origin" hubs. Illustrative only — the feed exposes the
// victim country and crew, not attacker geolocation.
const HUBS: { name: string; coord: [number, number] }[] = [
  { name: "E. Europe", coord: [40, 55] },
  { name: "E. Asia", coord: [110, 34] },
];

type CountItem = { name: string; count: number; countryName?: string };

function AttackArc({
  projection,
  from,
  to,
  color,
  delay,
  dur,
}: {
  projection: GeoProjection;
  from: [number, number];
  to: [number, number];
  color: string;
  delay: number;
  dur: number;
}) {
  const s = projection(from);
  const e = projection(to);
  if (!s || !e) return null;
  const [sx, sy] = s;
  const [ex, ey] = e;
  const mx = (sx + ex) / 2;
  const my = (sy + ey) / 2;
  const dx = ex - sx;
  const dy = ey - sy;
  const dist = Math.hypot(dx, dy) || 1;
  const lift = Math.min(150, dist * 0.42);
  // control point lifted perpendicular to the chord, nudged up so beams bow over the globe
  const cx = mx - (dy / dist) * lift;
  const cy = my + (dx / dist) * lift - Math.abs(lift) * 0.2;
  const d = `M${sx},${sy} Q${cx},${cy} ${ex},${ey}`;
  return (
    <g>
      <path d={d} fill="none" stroke={color} strokeWidth={0.6} opacity={0.35} />
      <path
        d={d}
        fill="none"
        stroke={color}
        strokeWidth={1.8}
        strokeLinecap="round"
        strokeDasharray="12 300"
        opacity={1}
        filter="url(#beamGlow)"
      >
        <animate attributeName="stroke-dashoffset" from="312" to="0" dur={`${dur}s`} begin={`${delay}s`} repeatCount="indefinite" />
      </path>
      <circle r={2.8} fill={BEAM_DOT} filter="url(#beamGlow)">
        <animate attributeName="opacity" values="0;1;1;0" keyTimes="0;0.1;0.85;1" dur={`${dur}s`} begin={`${delay}s`} repeatCount="indefinite" />
        <animateMotion dur={`${dur}s`} begin={`${delay}s`} repeatCount="indefinite" path={d} />
      </circle>
    </g>
  );
}

export function ThreatWorldMap({ countries, className }: { countries: CountItem[]; className?: string }) {
  const [geographies, setGeographies] = useState<Feature<Geometry>[] | null>(null);
  const [projection, setProjection] = useState<GeoProjection | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetch("/data/world-countries-110m.json")
      .then((r) => r.json())
      .then((topo) => {
        if (cancelled) return;
        const fc = feature(topo, topo.objects.countries) as unknown as FeatureCollection;
        const land = fc.features.filter((f) => (f.properties?.name as string) !== "Antarctica");
        const proj = geoEqualEarth().fitExtent(
          [[12, 12], [W - 12, H - 12]],
          { type: "FeatureCollection", features: land } as FeatureCollection,
        );
        setGeographies(land as Feature<Geometry>[]);
        setProjection(() => proj);
      })
      .catch(() => { /* map is decorative; ignore load errors */ });
    return () => { cancelled = true; };
  }, []);

  const maxCount = Math.max(1, ...countries.map((c) => c.count));
  const points = useMemo(
    () =>
      countries
        .map((c) => ({ ...c, coord: COUNTRY_COORDS[c.name] }))
        .filter((c): c is CountItem & { coord: [number, number] } => Array.isArray(c.coord)),
    [countries],
  );
  const arcs = useMemo(
    () =>
      points.slice(0, 8).map((t, i) => ({
        from: HUBS[i % HUBS.length].coord,
        to: t.coord,
        delay: i * 0.32,
        dur: 2 + (i % 3) * 0.4,
      })),
    [points],
  );

  return (
    <div className={className}>
      <ComposableMap
        projection={(projection ?? "geoEqualEarth") as unknown as string}
        width={W}
        height={H}
        style={{ width: "100%", height: "auto" }}
      >
        <defs>
          <filter id="beamGlow" x="-60%" y="-60%" width="220%" height="220%">
            <feGaussianBlur stdDeviation="2.2" result="b" />
            <feMerge>
              <feMergeNode in="b" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>
        <Geographies geography="/data/world-countries-110m.json">
          {({ geographies: geos }) =>
            geos
              .filter((g) => g.properties.name !== "Antarctica")
              .map((g) => (
                <Geography
                  key={g.rsmKey}
                  geography={g}
                  fill={COUNTRY_FILL}
                  stroke={COUNTRY_STROKE}
                  strokeWidth={0.4}
                  style={{
                    default: { outline: "none" },
                    hover: { outline: "none", fill: "#1d2c49" },
                    pressed: { outline: "none" },
                  }}
                />
              ))
          }
        </Geographies>

        {projection && (
          <>
            {/* attack beams: symbolic origin hubs → real victim countries */}
            <g>
              {arcs.map((a, i) => (
                <AttackArc
                  key={i}
                  projection={projection}
                  from={a.from}
                  to={a.to}
                  color={BEAM}
                  delay={a.delay}
                  dur={a.dur}
                />
              ))}
            </g>

            {/* victim country markers, sized by claimed-victim count */}
            {points.map((p) => {
              const r = 3 + (p.count / maxCount) * 12;
              return (
                <Marker key={p.name} coordinates={p.coord}>
                  <circle r={r} fill={VICTIM} opacity={0.18}>
                    <animate attributeName="r" values={`${r};${r * 1.3};${r}`} dur="2.6s" repeatCount="indefinite" />
                    <animate attributeName="opacity" values="0.18;0.05;0.18" dur="2.6s" repeatCount="indefinite" />
                  </circle>
                  <circle r={Math.max(1.8, r * 0.32)} fill={VICTIM} filter="url(#beamGlow)" />
                </Marker>
              );
            })}

            {/* symbolic origin hubs */}
            {HUBS.map((h) => (
              <Marker key={h.name} coordinates={h.coord}>
                <circle r={5} fill="none" stroke={HUB} strokeWidth={1.3} opacity={0.9}>
                  <animate attributeName="r" values="5;8;5" dur="2.4s" repeatCount="indefinite" />
                  <animate attributeName="opacity" values="0.9;0.2;0.9" dur="2.4s" repeatCount="indefinite" />
                </circle>
                <circle r={2} fill={HUB} filter="url(#beamGlow)" />
              </Marker>
            ))}
          </>
        )}
      </ComposableMap>
    </div>
  );
}
