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
import { checkDNSBL, checkDNSBLBatch } from "@/services/threatApi";
import { useToast } from "@/hooks/use-toast";
import { PageLayout } from "@/components/PageLayout";
import { useLanguage } from "@/contexts/LanguageContext";

import DNSBL_PROVIDERS from "../config/dnsblProviders.json";

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

        // Process in batches of 50 to optimize network load and request count
        const BATCH_SIZE = 50;
        const providersList = [...DNSBL_PROVIDERS];
        const batches: string[][] = [];
        
        for (let i = 0; i < providersList.length; i += BATCH_SIZE) {
            batches.push(providersList.slice(i, i + BATCH_SIZE));
        }

        // Process up to 4 batches concurrently to resolve fast while maintaining order
        const CONCURRENCY = 4;
        const queue = [...batches];
        
        const runWorker = async () => {
            while (queue.length > 0) {
                const batch = queue.shift();
                if (!batch || batch.length === 0) break;
                
                const startTime = performance.now();
                try {
                    const batchResults = await checkDNSBLBatch(query, batch);
                    const endTime = performance.now();
                    const latency = Math.round((endTime - startTime) / batch.length);

                    setResults(prev => prev.map(r => {
                        if (batch.includes(r.provider)) {
                            const res = batchResults[r.provider] || { listed: false, status: t('error'), error: "No response" };
                            return {
                                ...r,
                                listed: res.listed,
                                status: res.status === 'Error' ? t('error') : (res.listed ? res.status : (res.status === 'Timeout' ? t('timeout') || 'Timeout' : t('clean'))),
                                loading: false,
                                addresses: res.addresses,
                                error: res.error,
                                responseTime: latency
                            };
                        }
                        return r;
                    }));
                } catch (error) {
                    const endTime = performance.now();
                    const latency = Math.round(endTime - startTime);
                    setResults(prev => prev.map(r => {
                        if (batch.includes(r.provider)) {
                            return {
                                ...r,
                                listed: false,
                                status: t('error'),
                                loading: false,
                                error: "Failed to check",
                                responseTime: latency
                            };
                        }
                        return r;
                    }));
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
        <PageLayout bare>
            <div className={`flex-1 p-4 md:p-8 flex flex-col ${results.length === 0 ? "justify-center min-h-[50vh]" : ""} transition-all duration-500`}>
                <div className={`w-full transition-all duration-500 ${results.length === 0 ? "max-w-3xl mx-auto space-y-6 py-6" : "max-w-7xl mx-auto space-y-8"}`}>

                    {/* Page Header */}
                    <header className={results.length === 0 ? "text-center mb-2" : "mb-2"}>
                        <h1 className="text-3xl font-semibold tracking-tight">{t('checkIpReputation')}</h1>
                        <p className={`text-muted-foreground mt-2 leading-relaxed ${results.length === 0 ? "max-w-2xl mx-auto" : ""}`}>
                            {t('dnsblDescription', { count: DNSBL_PROVIDERS.length })}
                        </p>
                    </header>

                    {/* Search Panel — flat, ThreatBrief style */}
                    <div className={`w-full ${results.length === 0 ? "max-w-2xl mx-auto" : "max-w-none"}`}>
                        <form onSubmit={handleSearch} className="flex flex-col sm:flex-row gap-2 rounded-xl bg-muted/40 p-2">
                            <div className="flex items-center gap-2 flex-1 px-2">
                                <Shield className="h-4 w-4 text-muted-foreground shrink-0" />
                                <Input
                                    placeholder={t('enterIp')}
                                    value={query}
                                    onChange={(e) => setQuery(e.target.value)}
                                    className="flex-1 border-0 bg-transparent shadow-none focus-visible:ring-0 px-0"
                                />
                            </div>
                            <Button type="submit" disabled={isScanning} className="gap-2 shrink-0">
                                {isScanning ? <RotateCw className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
                                <span>{isScanning ? t('scanning') : t('scan')}</span>
                            </Button>
                        </form>

                        {/* Presets / IP Suggestions */}
                        <div className="flex flex-wrap items-center gap-1.5 text-xs text-muted-foreground mt-2 px-1">
                            <span className="font-medium">{language === 'pt' ? "Sugestões de IP:" : "IP Suggestions:"}</span>
                            {PRESETS.map(ip => (
                                <button
                                    key={ip}
                                    type="button"
                                    onClick={() => setQuery(ip)}
                                    className="px-2 py-0.5 rounded-lg bg-muted/60 hover:bg-primary/15 hover:text-primary transition-colors font-mono"
                                >
                                    {ip}
                                </button>
                            ))}
                        </div>
                    </div>

                    {/* Scan Status & Analytics Panel */}
                    {results.length > 0 && (
                        <div className="space-y-6 animate-fade-in">
                            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                                
                                {/* A: Circular Progress Ring */}
                                <Card className="border-primary/10 bg-muted/40  shadow-sm relative overflow-hidden flex flex-col justify-between">
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
                                <Card className="border-primary/10 bg-muted/40  shadow-sm flex flex-col justify-between">
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
                                                            className="bg-primary/80 transition-all duration-300"
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
                                                <span className="h-2 w-2 rounded-full bg-primary" />
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
                                <Card className="border-primary/10 bg-muted/40  shadow-sm flex flex-col justify-between">
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
                            <Card className="border-primary/10 bg-muted/40  shadow-md p-4">
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
                                <div className="p-12 border border-dashed border-primary/10 rounded-xl text-center bg-muted/40 ">
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
                                                        ? 'border-primary/15 bg-muted/40 animate-pulse shadow-sm shadow-primary/2' 
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
        </PageLayout>
    );
};

export default DnsblCheck;

