import { useState, useMemo } from "react";
import { Link } from "react-router-dom";
import { 
    ArrowLeft, Search, Shield, AlertTriangle, CheckCircle, RotateCw, 
    Home, Share2, Mail, BookOpen, Clock, Check, AlertCircle, X, 
    ChevronDown, ChevronUp, BarChart2, Filter, Copy, Info, CheckSquare 
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { checkDNSBL } from "@/services/threatApi";
import { useToast } from "@/hooks/use-toast";
import { Footer } from "@/components/Footer";
import { useLanguage } from "@/contexts/LanguageContext";
import { useSidebar } from "@/contexts/SidebarContext";
import { Header } from "@/components/Header";

const DNSBL_PROVIDERS = [
    "0outspam.fusionzero.com",
    "0spam-killlist.fusionzero.com",
    "0spam.fusionzero.com",
    "0spamtrust.fusionzero.com",
    "0spamurl.fusionzero.com",
    "88.blocklist.zap",
    "ab.surbl.org",
    "abuse-contacts.abusix.org",
    "abuse.rfc-clueless.org",
    "abuse.rfc-ignorant.org",
    "accept.the-carrot-and-the-stick.com",
    "access.atlbl.net",
    "accredit.habeas.com",
    "admin.bl.kundenserver.de",
    "adult.rhs.mailpolice.com",
    "adv.rhs.mailpolice.com",
    "ahbl.dnsbl.net.au",
    "ahrh.dnsbl.net.au",
    "all.ascc.dnsbl.bit.nl",
    "all.dnsbl.bit.nl",
    "all.rbl.jp",
    "all.rbl.kropka.net",
    "all.rbl.webiron.net",
    "all.s5h.net",
    "all.spam-rbl.fr",
    "all.spamblock.unit.liu.se",
    "all.v6.ascc.dnsbl.bit.nl",
    "any.dnsl.ipquery.org",
    "arspam.buanzo.org",
    "asiaspam.spamblocked.com",
    "assholes.madscience.nl",
    "b.barracudacentral.org",
    "babl.rbl.webiron.net",
    "backscatter.rbl.kropka.net",
    "backscatter.spameatingmonkey.net",
    "bad.psky.me",
    "badconf.rhsbl.sorbs.net",
    "badhost.stopspam.org",
    "badnets.spameatingmonkey.net",
    "bb.barracudacentral.org",
    "bitonly.dnsbl.bit.nl",
    "bl.blbl.org",
    "bl.blocklist.de",
    "bl.blueshore.net",
    "bl.borderworlds.dk",
    "bl.csma.biz",
    "bl.deadbeef.com",
    "bl.drmx.org",
    "bl.emailbasura.org",
    "bl.fmb.la",
    "bl.ipv6.spameatingmonkey.net",
    "bl.konstant.no",
    "bl.mailspike.net",
    "bl.mav.com.br",
    "bl.mipspace.com",
    "bl.nszones.com",
    "bl.open-whois.org",
    "bl.redhatgate.com",
    "bl.reynolds.net.au",
    "bl.scientificspam.net",
    "bl.score.senderscore.com",
    "bl.scrollout.com",
    "bl.shlink.org",
    "bl.spam-trap.net",
    "bl.spamcannibal.org",
    "bl.spamcop.net",
    "bl.spameatingmonkey.net",
    "bl.spamstinks.com",
    "bl.starloop.com",
    "bl.suomispam.net",
    "bl.technovision.dk",
    "bl.techtheft.info",
    "black.junkemailfilter.com",
    "black.uribl.com",
    "blackhole.compu.net",
    "blackhole.securitysage.com",
    "blackholes.2mbit.com",
    "blackholes.alphanet.ch",
    "blackholes.brainerd.net",
    "blackholes.easynet.nl",
    "blackholes.five-ten-sg.com",
    "blackholes.intersil.net",
    "blackholes.mail-abuse.org",
    "blackholes.sandes.dk",
    "blackholes.uceb.org",
    "blackholes.wirehub.net",
    "blacklist.fpsn.net",
    "blacklist.hostkarma.com",
    "blacklist.informationwave.net",
    "blacklist.netcore.co.in",
    "blacklist.sci.kun.nl",
    "blacklist.sci.ru.nl",
    "blacklist.spambag.org",
    "blacklist.woody.ch",
    "block.ascams.com",
    "block.blars.org",
    "block.dnsbl.sorbs.net",
    "block.rhs.mailpolice.com",
    "block.stopspam.org",
    "blocked.asgardnet.org",
    "blocked.hilli.dk",
    "blocklist.squawk.com",
    "blocklist2.squawk.com",
    "bogons.cymru.com",
    "bogons.dnsiplists.completewhois.com",
    "bsb.empty.us",
    "bsb.spamlookup.net",
    "bulk.rhs.mailpolice.com",
    "cabl.rbl.webiron.net",
    "cart00ney.surriel.com",
    "catchspam.com",
    "cbl.abuseat.org",
    "cbl.anti-spam.org.cn",
    "cblless.anti-spam.org.cn",
    "cblplus.anti-spam.org.cn",
    "cbs.lumbercartel.org",
    "cdl.anti-spam.org.cn",
    "cidr.bl.mcafee.com",
    "cml.anti-spam.org.cn",
    "combined.abuse.ch",
    "combined.rbl.msrbl.net",
    "contacts.abuse.net",
    "country.dnsbl.solid.net",
    "country.dnsbl.souphost.com",
    "country.netop.org",
    "crawler.rbl.webiron.net",
    "csi.cloudmark.com",
    "db.rurbl.ru",
    "dbl.spamhaus.org",
    "dbl.suomispam.net",
    "delayed-outputs.orbs.org",
    "dev.null.dk",
    "dhcp.tqmcube.com",
    "dialup.blacklist.jippg.org",
    "dialup.drbl.sandy.ru",
    "dialup.rbl.kropka.net",
    "dialups.mail-abuse.org",
    "dialups.visi.com",
    "dmm.shlink.org",
    "dnsbl-0.uceprotect.net",
    "dnsbl-1.uceprotect.net",
    "dnsbl-2.uceprotect.net",
    "dnsbl-3.uceprotect.net",
    "dnsbl.abuse.ch",
    "dnsbl.ahbl.org",
    "dnsbl.allgeek.net",
    "dnsbl.antispam.or.id",
    "dnsbl.burnt-tech.com",
    "dnsbl.calivent.com.pe",
    "dnsbl.cbn.net.id",
    "dnsbl.clue-by-4.org",
    "dnsbl.cmbix.com",
    "dnsbl.cobion.com",
    "dnsbl.cyberlogic.net",
    "dnsbl.delink.net",
    "dnsbl.dronebl.org",
    "dnsbl.httpbl.org",
    "dnsbl.ioerror.us",
    "dnsbl.ipocalypse.net",
    "dnsbl.isoc.bg",
    "dnsbl.justspam.org",
    "dnsbl.kempt.net",
    "dnsbl.mags.net",
    "dnsbl.openresolvers.org",
    "dnsbl.othello.ch",
    "dnsbl.pagedirect.net",
    "dnsbl.rizon.net",
    "dnsbl.rv-soft.info",
    "dnsbl.rymsho.ru",
    "dnsbl.solid.net",
    "dnsbl.sorbs.net",
    "dnsbl.spfbl.net",
    "dnsbl.stopspam.org",
    "dnsbl.tqmcube.com",
    "dnsbl.zapbl.net",
    "dnsblchile.org",
    "dnsrbl.org",
    "dnsrbl.swinog.ch",
    "dnswl.leisi.net",
    "drone.abuse.ch",
    "dronebl.noderebellion.net",
    "dsbl.dnsbl.net.au",
    "dsn.bl.rfc-ignorant.de",
    "dsn.rfc-clueless.org",
    "dsn.rfc-ignorant.org",
    "dul.dnsbl.borderware.com",
    "dul.dnsbl.sorbs.net",
    "dul.orca.bc.ca",
    "dul.ru",
    "dun.dnsrbl.net",
    "dunk.dnsbl.tuxad.de",
    "dyn.nszones.com",
    "dyn.shlink.org",
    "dynablock.easynet.nl",
    "dynablock.sorbs.net",
    "dynamic.dnsbl.rangers.eu.org",
    "dynamic.rhs.mailpolice.com",
    "elitist.rfc-clueless.org",
    "endl.dnsbl.net.au",
    "escalations.dnsbl.sorbs.net",
    "eswlrev.dnsbl.rediris.es",
    "eurospam.spamblocked.com",
    "feb.spamlab.com",
    "fnrbl.fast.net",
    "forbidden.icm.edu.pl",
    "fraud.rhs.mailpolice.com",
    "free.v4bl.org",
    "fresh.spameatingmonkey.net",
    "fresh10.spameatingmonkey.net",
    "fresh15.spameatingmonkey.net",
    "geobl.spamanalysis.org",
    "geobl.spameatingmonkey.net",
    "gl.suomispam.net",
    "grey.uribl.com",
    "hbl.atlbl.net",
    "hijacked.dnsiplists.completewhois.com",
    "hostkarma.junkemailfilter.com",
    "http.dnsbl.sorbs.net",
    "httpbl.abuse.ch",
    "iadb.isipp.com",
    "images.rbl.msrbl.net",
    "intercept.datapacket.net",
    "ip.rbl.kropka.net",
    "ip.v4bl.org",
    "ipal.ahbl.org",
    "ipbl.mailhosts.org",
    "ipbl.zeustracker.abuse.ch",
    "ips.backscatterer.org",
    "ips.whitelisted.org",
    "ipv6.all.dnsbl.bit.nl",
    "ipv6.all.s5h.net",
    "ipv6.blacklist.woody.ch",
    "ipv6.rbl.choon.net",
    "ircbl.ahbl.org",
    "jp.dialup.blacklist.jippg.org",
    "jp.surbl.org",
    "ko.tqmcube.com",
    "l1.spews.dnsbl.sorbs.net",
    "l2.spews.dnsbl.sorbs.net",
    "lame.dnsbl.rangers.eu.org",
    "list.blogspambl.com",
    "list.dnswl.org",
    "lookup.dnsbl.iip.lu",
    "mail-abuse.blacklist.jippg.org",
    "mailabusedatabase.com",
    "misc.dnsbl.sorbs.net",
    "mtawlrev.dnsbl.rediris.es",
    "multi.surbl.org",
    "multi.uribl.com",
    "netbl.spameatingmonkey.net",
    "netblock.pedantic.org",
    "netblockbl.spamgrouper.to",
    "new.dnsbl.sorbs.net",
    "nobl.junkemailfilter.com",
    "nomail.rhsbl.sorbs.net",
    "noservers.dnsbl.sorbs.net",
    "nospam.ant.pl",
    "nsbl.fmb.la",
    "ob.surbl.org",
    "old.dnsbl.sorbs.net",
    "op.rbl.kropka.net",
    "opm.tornevall.org",
    "or.rbl.kropka.net",
    "outputs.orbs.org",
    "owfs.dnsbl.net.au",
    "pbl.spamhaus.org",
    "pdl.bofh.it",
    "ph.surbl.org",
    "phishing.rbl.msrbl.net",
    "pool.dnsbl.solid.net",
    "porn.rhs.mailpolice.com",
    "ppbl.beat.st",
    "prc.tqmcube.com",
    "problems.dnsbl.sorbs.net",
    "proxies.dnsbl.sorbs.net",
    "proxy.block.transip.nl",
    "psbl.surriel.com",
    "pss.spambusters.org.ar",
    "public.sarbl.org",
    "rabl.nuclearelephant.com",
    "rbl.abuse.ro",
    "rbl.atlbl.net",
    "rbl.blockedservers.com",
    "rbl.choon.net",
    "rbl.dns-servicios.com",
    "rbl.efnet.org",
    "rbl.efnetrbl.org",
    "rbl.eznettools.com",
    "rbl.fasthosts.co.uk",
    "rbl.firstbase.com",
    "rbl.init1.nl",
    "rbl.interserver.net",
    "rbl.iprange.net",
    "rbl.ipv6-world.net",
    "rbl.jp",
    "rbl.lugh.ch",
    "rbl.mail-abuse.org",
    "rbl.megarbl.net",
    "rbl.openrbl.org",
    "rbl.orbitrbl.com",
    "rbl.pil.dk",
    "rbl.polarcomm.net",
    "rbl.realtimeblacklist.com",
    "rbl.rope.net",
    "rbl.schulte.org",
    "rbl.snark.net",
    "rbl.spamlab.com",
    "rbl.stonehenge.com",
    "rbl.suresupport.com",
    "rbl.talkactive.net",
    "rbl.triumf.ca",
    "rbl2.triumf.ca",
    "recent.dnsbl.sorbs.net",
    "red.uribl.com",
    "relays.bl.kundenserver.de",
    "relays.dnsbl.sorbs.net",
    "relays.mail-abuse.org",
    "relays.nether.net",
    "relays.nthelp.com",
    "relays.ordb.org",
    "rep.mailspike.net",
    "residential.block.transip.nl",
    "rhsbl.ahbl.org",
    "rhsbl.mailhosts.org",
    "rhsbl.rymsho.ru",
    "rhsbl.scientificspam.net",
    "rhsbl.shlink.org",
    "rhsbl.sorbs.net",
    "rhsbl.zapbl.net",
    "robot.bl.techtheft.info",
    "rwl.choon.net",
    "sa.fmb.la",
    "safe.dnsbl.sorbs.net",
    "sbl-xbl.spamhaus.org",
    "sbl.spamhaus.org",
    "sc.surbl.org",
    "service.mailblacklist.com",
    "short.fmb.la",
    "smtp.dnsbl.sorbs.net",
    "socks.dnsbl.sorbs.net",
    "sorbs.dnsbl.net.au",
    "spam.abuse.ch",
    "spam.dnsbl.anonmails.de",
    "spam.dnsbl.sorbs.net",
    "spam.exsilia.net",
    "spam.olsentech.net",
    "spam.pedantic.org",
    "spam.rbl.msrbl.net",
    "spam.tqmcube.com",
    "spamdomain.block.transip.nl",
    "spamguard.leadmon.net",
    "spamips.rbl.shub-inter.net",
    "spamrbl.imp.ch",
    "spamsites.dnsbl.net.au",
    "spamsources.dnsbl.info",
    "spamsources.fabel.dk",
    "spamtrap.trblspam.com",
    "spbl.bl.winbots.org",
    "spider.realtimespiderlist.com",
    "st.technovision.dk",
    "stabl.rbl.webiron.net",
    "superblock.ascams.com",
    "swl.spamhaus.org",
    "tor.ahbl.org",
    "tor.dan.me.uk",
    "tor.efnet.org",
    "torexit.dan.me.uk",
    "truncate.gbudb.net",
    "trust.trustmymail.org",
    "trusted.nether.net",
    "ubl.lashback.com",
    "ubl.nszones.com",
    "ubl.unsubscore.com",
    "unsure.nether.net",
    "uri.blacklist.woody.ch",
    "uribl.abuse.ro",
    "uribl.pofon.foobar.hu",
    "uribl.spameatingmonkey.net",
    "uribl.swinog.ch",
    "uribl.zeustracker.abuse.ch",
    "urired.spameatingmonkey.net",
    "url.rbl.jp",
    "v4.fullbogons.cymru.com",
    "v6.fullbogons.cymru.com",
    "virbl.bit.nl",
    "virbl.dnsbl.bit.nl",
    "virus.rbl.msrbl.net",
    "vouch.dwl.spamhaus.org",
    "wbl.triumf.ca",
    "web.dnsbl.sorbs.net",
    "web.rbl.msrbl.net",
    "white.uribl.com",
    "whitelist.sci.kun.nl",
    "whitelist.sci.ru.nl",
    "wl.mailspike.net",
    "wl.nszones.com",
    "wl.shlink.org",
    "wl.trusted-forwarder.org",
    "world.tqmcube.com",
    "worm.dnsbl.rangers.eu.org",
    "wormrbl.imp.ch",
    "worms-bl.kundenserver.de",
    "ws.surbl.org",
    "xbl.spamhaus.org",
    "ybl.megacity.org",
    "z.mailspike.net",
    "zebl.zoneedit.com",
    "zen.spamhaus.org",
    "zombie.dnsbl.sorbs.net",
    "ztl.dorkslayers.com"
];

interface DNSBLResult {
    provider: string;
    listed: boolean;
    status: string;
    loading: boolean;
    error?: string;
    addresses?: string[];
    responseTime?: number;
}

const PRESETS = ["8.8.8.8", "1.1.1.1", "9.9.9.9", "185.220.101.5"];

const DnsblCheck = () => {
    const { isCollapsed } = useSidebar();
    const [query, setQuery] = useState("");
    const [results, setResults] = useState<DNSBLResult[]>([]);
    const [isScanning, setIsScanning] = useState(false);
    
    // UI filters and details
    const [filterType, setFilterType] = useState<"all" | "listed" | "clean" | "pending">("all");
    const [searchFilter, setSearchFilter] = useState("");
    const [expandedProviders, setExpandedProviders] = useState<Record<string, boolean>>({});

    const { toast } = useToast();
    const { t, language } = useLanguage();

    const handleSearch = async (e: React.FormEvent) => {
        e.preventDefault();

        if (!query) {
            toast({
                title: t('error'),
                description: t('invalidIp'),
                variant: "destructive",
            });
            return;
        }

        // Basic IP validation
        const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
        if (!ipRegex.test(query)) {
            toast({
                title: t('invalidInput'),
                description: t('invalidIp'),
                variant: "destructive",
            });
            return;
        }

        setIsScanning(true);
        setFilterType("all");
        setSearchFilter("");
        setExpandedProviders({});

        // Initialize results
        const initialResults = DNSBL_PROVIDERS.map(provider => ({
            provider,
            listed: false,
            status: t('pending'),
            loading: true
        }));
        setResults(initialResults);

        // Process with a worker queue to avoid blocking fast providers with slow ones
        const CONCURRENCY = 6; // Optimal concurrency for browser HTTP/1.1 limits
        const queue = [...DNSBL_PROVIDERS];
        
        const runWorker = async () => {
            while (queue.length > 0) {
                const provider = queue.shift();
                if (!provider) break;
                
                const startTime = performance.now();
                try {
                    const result = await checkDNSBL(query, provider);
                    const endTime = performance.now();
                    const latency = Math.round(endTime - startTime);

                    setResults(prev => prev.map(r =>
                        r.provider === provider
                            ? { ...r, listed: result.listed, status: result.status, loading: false, addresses: result.addresses, error: result.error, responseTime: latency }
                            : r
                    ));
                } catch (error) {
                    const endTime = performance.now();
                    const latency = Math.round(endTime - startTime);
                    setResults(prev => prev.map(r =>
                        r.provider === provider
                            ? { ...r, listed: false, status: t('error'), loading: false, error: "Failed to check", responseTime: latency }
                            : r
                    ));
                }
            }
        };

        // Start worker pool
        const workers = Array.from({ length: CONCURRENCY }, () => runWorker());
        await Promise.all(workers);

        setIsScanning(false);
    };

    const toggleExpand = (provider: string) => {
        setExpandedProviders(prev => ({
            ...prev,
            [provider]: !prev[provider]
        }));
    };

    // Calculate core statistics
    const listedCount = results.filter(r => r.listed).length;
    const totalChecked = results.filter(r => !r.loading).length;
    const cleanCount = results.filter(r => !r.listed && !r.loading).length;
    const pendingCount = results.filter(r => r.loading).length;
    const percentage = results.length > 0 ? Math.round((totalChecked / results.length) * 100) : 0;

    // Calculate Latency Distribution stats
    const latencyStats = useMemo(() => {
        const completed = results.filter(r => !r.loading);
        if (completed.length === 0) return { fast: 0, normal: 0, slow: 0, error: 0, avg: 0 };

        const latencies = completed
            .filter(r => r.responseTime !== undefined && r.status !== t('error') && !r.error)
            .map(r => r.responseTime as number);

        const avg = latencies.length > 0 ? Math.round(latencies.reduce((a, b) => a + b, 0) / latencies.length) : 0;

        let fast = 0;
        let normal = 0;
        let slow = 0;
        let error = 0;

        completed.forEach(r => {
            if (r.status === t('error') || r.error) {
                error++;
            } else if (r.responseTime !== undefined) {
                if (r.responseTime < 500) fast++;
                else if (r.responseTime <= 1000) normal++;
                else slow++;
            } else {
                error++;
            }
        });

        return { fast, normal, slow, error, avg };
    }, [results, t]);

    // Filtered and sorted results for rendering
    const filteredResults = useMemo(() => {
        let items = results;

        if (filterType === "listed") {
            items = items.filter(r => r.listed);
        } else if (filterType === "clean") {
            items = items.filter(r => !r.listed && !r.loading && r.status !== t('error') && !r.error);
        } else if (filterType === "pending") {
            items = items.filter(r => r.loading);
        }

        if (searchFilter.trim() !== "") {
            const searchLower = searchFilter.toLowerCase();
            items = items.filter(r => r.provider.toLowerCase().includes(searchLower));
        }

        return [...items].sort((a, b) => {
            if (a.listed && !b.listed) return -1;
            if (!a.listed && b.listed) return 1;
            return a.provider.localeCompare(b.provider);
        });
    }, [results, filterType, searchFilter, t]);

    const handleShare = () => {
        const listed = results.filter(r => r.listed).map(r => r.provider);
        const cleanCount = results.filter(r => !r.listed && !r.loading).length;

        const text = `DNSBL Check for ${query}\n` +
            `Listed in ${listed.length} blocklists\n` +
            `Clean in ${cleanCount} blocklists\n\n` +
            (listed.length > 0 ? `Listed in:\n${listed.join('\n')}` : "Clean in all checked lists.");

        if (navigator.share) {
            navigator.share({
                title: `DNSBL Report - ${query}`,
                text: text,
            }).catch(() => {
                navigator.clipboard.writeText(text);
                toast({
                    title: t('copied'),
                    description: t('shareLinkCopied'),
                });
            });
        } else {
            navigator.clipboard.writeText(text);
            toast({
                title: t('copied'),
                description: t('shareLinkCopied'),
            });
        }
    };
    return (
        <div className={`min-h-screen bg-background flex flex-col transition-all duration-300 ${isCollapsed ? "lg:pl-20" : "lg:pl-64"}`}>
            <Header showBackButton />

            <div className={`flex-1 p-4 md:p-8 flex flex-col ${results.length === 0 ? "justify-center min-h-[75vh]" : ""} transition-all duration-500`}>
                <div className={`w-full transition-all duration-500 ${results.length === 0 ? "max-w-3xl mx-auto space-y-6 py-6" : "max-w-7xl mx-auto space-y-8"}`}>

                    {/* Page Header */}
                    <div className={`transition-all duration-500 ${results.length === 0 ? "text-center space-y-4 mb-2" : "flex flex-col md:flex-row md:items-center justify-between gap-4 border-b pb-4"}`}>
                        <div className={`${results.length === 0 ? "space-y-3" : ""}`}>
                            <h2 className={`font-bold tracking-tight text-foreground transition-all duration-500 ${results.length === 0 ? "text-3xl sm:text-4xl bg-gradient-to-r from-primary via-primary/80 to-primary/60 bg-clip-text text-transparent" : "text-2xl"}`}>
                                {t('checkIpReputation')}
                            </h2>
                            <p className={`text-sm text-muted-foreground mt-1 transition-all duration-500 ${results.length === 0 ? "max-w-2xl mx-auto" : "max-w-none"}`}>
                                {t('dnsblDescription', { count: DNSBL_PROVIDERS.length })}
                            </p>
                        </div>
                    </div>

                    {/* Search Panel */}
                    <div className={`transition-all duration-500 w-full ${results.length === 0 ? "max-w-3xl mx-auto" : "max-w-none"}`}>
                        <Card className="border-primary/10 bg-card/25 backdrop-blur-xl shadow-xl rounded-3xl p-1">
                            <CardContent className="pt-6 space-y-4">
                                <form onSubmit={handleSearch} className="flex flex-col sm:flex-row gap-3">
                                    <div className="relative flex-1">
                                        <Shield className="absolute left-4 top-3.5 h-5 w-5 text-muted-foreground/75" />
                                        <Input
                                            placeholder={t('enterIp')}
                                            value={query}
                                            onChange={(e) => setQuery(e.target.value)}
                                            className="flex-1 text-sm h-12 pl-11 bg-background/40 focus-visible:ring-primary/30 border-primary/20 rounded-2xl placeholder:text-muted-foreground/50 text-foreground font-medium"
                                        />
                                    </div>
                                    <Button 
                                        type="submit" 
                                        disabled={isScanning} 
                                        size="lg" 
                                        className="h-12 px-8 font-semibold rounded-2xl bg-primary hover:bg-primary/95 text-primary-foreground flex items-center gap-2 shrink-0 transition-all shadow-md hover:shadow-lg"
                                    >
                                        {isScanning ? <RotateCw className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
                                        <span>{isScanning ? t('scanning') : t('scan')}</span>
                                    </Button>
                                </form>

                                {/* Presets / IP Suggestions */}
                                <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground/80 justify-center sm:justify-start pt-2 border-t border-border/10">
                                    <span className="font-semibold">{language === 'pt' ? "Sugestões de IP:" : "IP Suggestions:"}</span>
                                    <div className="flex flex-wrap gap-2">
                                        {PRESETS.map(ip => (
                                            <button
                                                key={ip}
                                                type="button"
                                                onClick={() => setQuery(ip)}
                                                className="px-2.5 py-1 rounded bg-muted/60 hover:bg-primary/15 hover:text-primary transition-all border border-primary/5 hover:border-primary/20 font-mono shadow-sm"
                                            >
                                                {ip}
                                            </button>
                                        ))}
                                    </div>
                                </div>
                            </CardContent>
                        </Card>
                    </div>

                    {/* Scan Status & Analytics Panel */}
                    {results.length > 0 && (
                        <div className="space-y-6 animate-fade-in">
                            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                                
                                {/* A: Circular Progress Ring */}
                                <Card className="border-primary/10 bg-card/40 backdrop-blur-md shadow-sm relative overflow-hidden flex flex-col justify-between">
                                    <CardHeader className="pb-2">
                                        <CardTitle className="text-sm font-bold uppercase tracking-wider text-muted-foreground flex items-center gap-2">
                                            <RotateCw className={`h-4 w-4 text-primary ${isScanning ? 'animate-spin' : ''}`} />
                                            {language === 'pt' ? "Progresso da Consulta" : "Query Progress"}
                                        </CardTitle>
                                    </CardHeader>
                                    <CardContent className="flex flex-col items-center justify-center py-6 space-y-4">
                                        <div className="relative flex items-center justify-center">
                                            {/* Progress Circular Gauge */}
                                            <svg className="w-32 h-32 transform -rotate-90">
                                                <circle
                                                    cx="64"
                                                    cy="64"
                                                    r="52"
                                                    stroke="currentColor"
                                                    strokeWidth="8"
                                                    fill="transparent"
                                                    className="text-muted/10 dark:text-muted/5"
                                                />
                                                <circle
                                                    cx="64"
                                                    cy="64"
                                                    r="52"
                                                    stroke="currentColor"
                                                    strokeWidth="8"
                                                    fill="transparent"
                                                    strokeDasharray={2 * Math.PI * 52}
                                                    strokeDashoffset={2 * Math.PI * 52 * (1 - percentage / 100)}
                                                    className={`transition-all duration-300 ${
                                                        isScanning 
                                                            ? 'text-primary' 
                                                            : listedCount > 0 
                                                                ? 'text-destructive' 
                                                                : 'text-green-500'
                                                    }`}
                                                />
                                            </svg>
                                            
                                            {/* Percentage inside circular bar */}
                                            <div className="absolute flex flex-col items-center justify-center">
                                                <span className="text-2xl font-black font-mono tracking-tighter">
                                                    {percentage}%
                                                </span>
                                                <span className="text-[10px] text-muted-foreground font-semibold uppercase tracking-wider">
                                                    {totalChecked}/{results.length}
                                                </span>
                                            </div>
                                        </div>

                                        <div className="text-center">
                                            {isScanning ? (
                                                <span className="text-xs font-semibold text-primary animate-pulse flex items-center gap-1.5 justify-center">
                                                    <span className="h-1.5 w-1.5 rounded-full bg-primary animate-ping" />
                                                    {t('scanning')} ({pendingCount} {language === 'pt' ? 'restantes' : 'left'})
                                                </span>
                                            ) : listedCount > 0 ? (
                                                <span className="text-xs font-bold text-destructive flex items-center gap-1.5 justify-center bg-destructive/10 px-3 py-1 rounded-full border border-destructive/20 shadow-sm animate-bounce">
                                                    <AlertTriangle className="h-3.5 w-3.5" />
                                                    {language === 'pt' ? `${listedCount} Detecções Encontradas` : `${listedCount} Detections Found`}
                                                </span>
                                            ) : (
                                                <span className="text-xs font-bold text-green-500 flex items-center gap-1.5 justify-center bg-green-500/10 px-3 py-1 rounded-full border border-green-500/20 shadow-sm">
                                                    <CheckCircle className="h-3.5 w-3.5" />
                                                    {language === 'pt' ? "IP Limpo e Seguro" : "IP Clean & Safe"}
                                                </span>
                                            )}
                                        </div>
                                    </CardContent>
                                </Card>

                                {/* B: Performance Latency Distribution */}
                                <Card className="border-primary/10 bg-card/40 backdrop-blur-md shadow-sm flex flex-col justify-between">
                                    <CardHeader className="pb-2">
                                        <CardTitle className="text-sm font-bold uppercase tracking-wider text-muted-foreground flex items-center gap-2">
                                            <Clock className="h-4 w-4 text-primary" />
                                            {language === 'pt' ? "Performance de Resposta" : "Response Performance"}
                                        </CardTitle>
                                    </CardHeader>
                                    <CardContent className="space-y-4 py-4">
                                        <div className="flex justify-between items-baseline border-b border-border/50 pb-2">
                                            <span className="text-xs text-muted-foreground font-semibold">{language === 'pt' ? "Média de Latência:" : "Average Latency:"}</span>
                                            <span className="text-xl font-bold font-mono text-primary">
                                                {latencyStats.avg > 0 ? `${latencyStats.avg}ms` : "N/A"}
                                            </span>
                                        </div>

                                        {/* Dynamic Latency Stacked Bar */}
                                        <div className="space-y-2">
                                            <div className="text-[11px] font-semibold text-muted-foreground uppercase tracking-wider flex justify-between">
                                                <span>{language === 'pt' ? "Distribuição de Latência" : "Latency Distribution"}</span>
                                                <span>{totalChecked} / {results.length}</span>
                                            </div>
                                            
                                            <div className="h-3.5 w-full bg-muted/40 rounded-full overflow-hidden flex shadow-inner border border-primary/5">
                                                {totalChecked > 0 ? (
                                                    <>
                                                        <div 
                                                            style={{ width: `${Math.max(2, (latencyStats.fast / totalChecked) * 100)}%` }} 
                                                            className="bg-green-500/80 transition-all duration-300"
                                                            title={`Fast (<500ms): ${latencyStats.fast}`}
                                                        />
                                                        <div 
                                                            style={{ width: `${Math.max(0, (latencyStats.normal / totalChecked) * 100)}%` }} 
                                                            className="bg-indigo-500/80 transition-all duration-300"
                                                            title={`Normal (500-1000ms): ${latencyStats.normal}`}
                                                        />
                                                        <div 
                                                            style={{ width: `${Math.max(0, (latencyStats.slow / totalChecked) * 100)}%` }} 
                                                            className="bg-amber-500/80 transition-all duration-300"
                                                            title={`Slow (>1000ms): ${latencyStats.slow}`}
                                                        />
                                                        <div 
                                                            style={{ width: `${Math.max(0, (latencyStats.error / totalChecked) * 100)}%` }} 
                                                            className="bg-red-500/80 transition-all duration-300"
                                                            title={`Errors: ${latencyStats.error}`}
                                                        />
                                                    </>
                                                ) : (
                                                    <div className="w-full bg-muted animate-pulse" />
                                                )}
                                            </div>
                                        </div>

                                        {/* Latency Legend Checklist */}
                                        <div className="grid grid-cols-2 gap-2 text-[10px] pt-1">
                                            <div className="flex items-center gap-1.5">
                                                <span className="h-2 w-2 rounded-full bg-green-500" />
                                                <span className="font-medium text-muted-foreground">{language === 'pt' ? "Rápido (<500ms):" : "Fast (<500ms):"}</span>
                                                <span className="font-bold font-mono">{latencyStats.fast}</span>
                                            </div>
                                            <div className="flex items-center gap-1.5">
                                                <span className="h-2 w-2 rounded-full bg-indigo-500" />
                                                <span className="font-medium text-muted-foreground">{language === 'pt' ? "Normal (0.5-1s):" : "Normal (0.5-1s):"}</span>
                                                <span className="font-bold font-mono">{latencyStats.normal}</span>
                                            </div>
                                            <div className="flex items-center gap-1.5">
                                                <span className="h-2 w-2 rounded-full bg-amber-500" />
                                                <span className="font-medium text-muted-foreground">{language === 'pt' ? "Lento (>1s):" : "Slow (>1s):"}</span>
                                                <span className="font-bold font-mono">{latencyStats.slow}</span>
                                            </div>
                                            <div className="flex items-center gap-1.5">
                                                <span className="h-2 w-2 rounded-full bg-red-500" />
                                                <span className="font-medium text-muted-foreground">{language === 'pt' ? "Erro/Timeout:" : "Error/Timeout:"}</span>
                                                <span className="font-bold font-mono">{latencyStats.error}</span>
                                            </div>
                                        </div>
                                    </CardContent>
                                </Card>

                                {/* C: Summary & Report Actions */}
                                <Card className="border-primary/10 bg-card/40 backdrop-blur-md shadow-sm flex flex-col justify-between">
                                    <CardHeader className="pb-2">
                                        <CardTitle className="text-sm font-bold uppercase tracking-wider text-muted-foreground flex items-center gap-2">
                                            <BarChart2 className="h-4 w-4 text-primary" />
                                            {language === 'pt' ? "Métricas de Segurança" : "Security Metrics"}
                                        </CardTitle>
                                    </CardHeader>
                                    <CardContent className="space-y-4 py-4 flex-1 flex flex-col justify-between">
                                        <div className="grid grid-cols-2 gap-3">
                                            <div className="p-2.5 rounded-lg border border-primary/5 bg-background/30 text-center">
                                                <div className={`text-xl font-bold font-mono ${listedCount > 0 ? 'text-destructive' : 'text-foreground'}`}>
                                                    {listedCount}
                                                </div>
                                                <div className="text-[9px] font-semibold text-muted-foreground uppercase tracking-wider">{t('listed')}</div>
                                            </div>
                                            <div className="p-2.5 rounded-lg border border-primary/5 bg-background/30 text-center">
                                                <div className="text-xl font-bold font-mono text-green-500">
                                                    {cleanCount}
                                                </div>
                                                <div className="text-[9px] font-semibold text-muted-foreground uppercase tracking-wider">{t('clean')}</div>
                                            </div>
                                            <div className="p-2.5 rounded-lg border border-primary/5 bg-background/30 text-center">
                                                <div className="text-xl font-bold font-mono text-primary">
                                                    {totalChecked}
                                                </div>
                                                <div className="text-[9px] font-semibold text-muted-foreground uppercase tracking-wider">{t('checked')}</div>
                                            </div>
                                            <div className="p-2.5 rounded-lg border border-primary/5 bg-background/30 text-center">
                                                <div className="text-xl font-bold font-mono text-muted-foreground">
                                                    {pendingCount}
                                                </div>
                                                <div className="text-[9px] font-semibold text-muted-foreground uppercase tracking-wider">{language === 'pt' ? "Restantes" : "Remaining"}</div>
                                            </div>
                                        </div>

                                        <Button 
                                            variant="outline" 
                                            className="w-full gap-2 border-primary/20 hover:bg-primary/5 transition-all text-xs font-semibold py-5" 
                                            onClick={handleShare}
                                            disabled={isScanning}
                                        >
                                            <Share2 className="h-4 w-4 text-primary" />
                                            <span>{t('shareReport')}</span>
                                        </Button>
                                    </CardContent>
                                </Card>

                            </div>

                            {/* Filters and Blocklists Grid Toolbar */}
                            <Card className="border-primary/10 bg-card/65 backdrop-blur-md shadow-md p-4">
                                <div className="flex flex-col sm:flex-row gap-4 items-center justify-between">
                                    
                                    {/* Search input for blocklist name */}
                                    <div className="relative w-full sm:max-w-xs">
                                        <Search className="absolute left-3 top-2.5 h-4 w-4 text-muted-foreground" />
                                        <Input
                                            placeholder={language === 'pt' ? "Filtrar por provedor..." : "Filter by provider..."}
                                            value={searchFilter}
                                            onChange={(e) => setSearchFilter(e.target.value)}
                                            className="pl-9 bg-background/50 border-primary/5 h-9 text-xs"
                                        />
                                        {searchFilter && (
                                            <button 
                                                onClick={() => setSearchFilter("")} 
                                                className="absolute right-2.5 top-2.5 hover:text-foreground text-muted-foreground"
                                            >
                                                <X className="h-4 w-4" />
                                            </button>
                                        )}
                                    </div>

                                    {/* Filters Tabs/Pills */}
                                    <div className="flex flex-wrap items-center gap-1.5 w-full sm:w-auto justify-start sm:justify-end">
                                        <span className="text-[10px] font-bold text-muted-foreground uppercase tracking-wider mr-2 hidden md:inline flex items-center gap-1">
                                            <Filter className="h-3 w-3" />
                                            {language === 'pt' ? "Filtrar Status:" : "Filter Status:"}
                                        </span>
                                        
                                        <Button
                                            variant={filterType === "all" ? "default" : "outline"}
                                            size="sm"
                                            className="h-8 text-xs font-medium px-3 rounded-full"
                                            onClick={() => setFilterType("all")}
                                        >
                                            {language === 'pt' ? "Todos" : "All"} ({results.length})
                                        </Button>
                                        
                                        <Button
                                            variant={filterType === "listed" ? "destructive" : "outline"}
                                            size="sm"
                                            className={`h-8 text-xs font-medium px-3 rounded-full ${
                                                filterType !== "listed" && listedCount > 0 
                                                    ? "border-destructive/30 text-destructive hover:bg-destructive/5" 
                                                    : ""
                                            }`}
                                            onClick={() => setFilterType("listed")}
                                        >
                                            {t('listed')} ({listedCount})
                                        </Button>

                                        <Button
                                            variant={filterType === "clean" ? "default" : "outline"}
                                            size="sm"
                                            className={`h-8 text-xs font-medium px-3 rounded-full ${
                                                filterType === "clean" 
                                                    ? "bg-green-600 hover:bg-green-700 text-white" 
                                                    : "border-green-500/20 text-green-500 hover:bg-green-500/5"
                                            }`}
                                            onClick={() => setFilterType("clean")}
                                        >
                                            {t('clean')} ({cleanCount})
                                        </Button>

                                        <Button
                                            variant={filterType === "pending" ? "secondary" : "outline"}
                                            size="sm"
                                            className="h-8 text-xs font-medium px-3 rounded-full"
                                            onClick={() => setFilterType("pending")}
                                        >
                                            {language === 'pt' ? "Pendente" : "Pending"} ({pendingCount})
                                        </Button>
                                    </div>
                                </div>
                            </Card>

                            {/* Providers Grid */}
                            {filteredResults.length === 0 ? (
                                <div className="p-12 border border-dashed border-primary/10 rounded-xl text-center bg-card/25 backdrop-blur-sm">
                                    <Info className="h-10 w-10 text-muted-foreground/50 mx-auto mb-3" />
                                    <p className="text-muted-foreground font-medium">
                                        {language === 'pt' ? "Nenhum provedor encontrado para a filtragem atual." : "No providers found matching current filters."}
                                    </p>
                                </div>
                            ) : (
                                <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5 gap-4">
                                    {filteredResults.map((result) => {
                                        const isExpanded = !!expandedProviders[result.provider];
                                        return (
                                            <Card 
                                                key={result.provider} 
                                                onClick={() => toggleExpand(result.provider)}
                                                className={`transition-all duration-300 cursor-pointer overflow-hidden border select-none ${
                                                    result.loading 
                                                        ? 'border-primary/15 bg-card/45 animate-pulse shadow-sm shadow-primary/2' 
                                                        : result.listed 
                                                            ? 'border-destructive/40 bg-destructive/5 shadow-md shadow-destructive/5 hover:border-destructive/70 scale-[1.01]' 
                                                            : 'border-border/60 hover:border-primary/30 hover:bg-accent/10 shadow-sm'
                                                }`}
                                            >
                                                <CardHeader className="p-4 pb-2">
                                                    <div className="flex items-center justify-between gap-2">
                                                        <CardTitle 
                                                            className="text-xs font-bold truncate w-full flex items-center gap-1.5" 
                                                            title={result.provider}
                                                        >
                                                            {result.provider}
                                                        </CardTitle>
                                                        
                                                        <div className="shrink-0">
                                                            {result.loading ? (
                                                                <RotateCw className="h-3.5 w-3.5 animate-spin text-primary" />
                                                            ) : result.listed ? (
                                                                <AlertTriangle className="h-3.5 w-3.5 text-destructive animate-pulse" />
                                                            ) : result.error ? (
                                                                <AlertCircle className="h-3.5 w-3.5 text-muted-foreground" />
                                                            ) : (
                                                                <CheckCircle className="h-3.5 w-3.5 text-green-500" />
                                                            )}
                                                        </div>
                                                    </div>
                                                </CardHeader>
                                                
                                                <CardContent className="p-4 pt-1 pb-3 space-y-2">
                                                    <div className="flex justify-between items-center text-[10px]">
                                                        {result.loading ? (
                                                            <span className="text-muted-foreground/80 font-medium">{t('checking')}</span>
                                                        ) : result.error ? (
                                                            <span className="text-destructive/80 font-medium font-mono text-[9px] truncate max-w-[80px]" title={result.error}>
                                                                {result.error}
                                                            </span>
                                                        ) : (
                                                            <span className={`font-bold uppercase tracking-wider ${result.listed ? "text-destructive" : "text-green-500"}`}>
                                                                {result.listed ? t('listed') : t('clean')}
                                                            </span>
                                                        )}

                                                        {result.responseTime !== undefined && (
                                                            <span className="text-[9px] text-muted-foreground font-mono bg-muted/65 px-1.5 py-0.5 rounded border border-border/30">
                                                                {result.responseTime}ms
                                                            </span>
                                                        )}
                                                    </div>

                                                    {/* Expansion Arrow for detailed information */}
                                                    {!result.loading && (
                                                        <div className="flex items-center justify-center pt-1 border-t border-border/30 text-[9px] text-muted-foreground font-semibold uppercase tracking-wider hover:text-primary transition-colors">
                                                            <span className="mr-1">
                                                                {isExpanded 
                                                                    ? (language === 'pt' ? 'Ocultar detalhes' : 'Hide details') 
                                                                    : (language === 'pt' ? 'Ver detalhes' : 'Show details')
                                                                }
                                                            </span>
                                                            {isExpanded ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
                                                        </div>
                                                    )}

                                                    {/* Expanded Content Drawer */}
                                                    {isExpanded && !result.loading && (
                                                        <div className="pt-2 text-[10px] space-y-1.5 animate-slide-in border-t border-dashed border-border/40 mt-1 select-text" onClick={e => e.stopPropagation()}>
                                                            {result.listed && result.addresses && result.addresses.length > 0 && (
                                                                <div className="space-y-1 bg-destructive/10 p-2 rounded border border-destructive/20">
                                                                    <div className="font-bold text-destructive uppercase tracking-wider text-[9px]">{language === 'pt' ? "Endereços Resolvidos:" : "Resolved Addresses:"}</div>
                                                                    <div className="font-mono text-muted-foreground whitespace-pre-wrap break-all">{result.addresses.join(", ")}</div>
                                                                </div>
                                                            )}
                                                            {result.error && (
                                                                <div className="bg-muted p-2 rounded text-destructive border border-border/40">
                                                                    <div className="font-bold uppercase text-[9px]">{language === 'pt' ? "Relatório de Erro:" : "Error Report:"}</div>
                                                                    <div className="font-mono text-muted-foreground whitespace-pre-wrap">{result.error}</div>
                                                                </div>
                                                            )}
                                                            {!result.listed && !result.error && (
                                                                <div className="bg-green-500/5 p-2 rounded text-green-500 border border-green-500/10">
                                                                    <div className="font-bold uppercase text-[9px]">{language === 'pt' ? "Diferencial de Segurança:" : "Security Clearance:"}</div>
                                                                    <div className="text-muted-foreground leading-normal">
                                                                        {language === 'pt' ? "Nenhum registro correspondente foi retornado por este provedor DNSBL. O IP está liberado." : "No matching records were returned by this DNSBL provider. The IP address is clear."}
                                                                    </div>
                                                                </div>
                                                            )}
                                                        </div>
                                                    )}
                                                </CardContent>
                                            </Card>
                                        );
                                    })}
                                </div>
                            )}
                        </div>
                    )}
                </div>
            </div>
            <Footer />
        </div>
    );
};

export default DnsblCheck;

