export interface WeeklyEditorialArticle {id:string;status:'ready'|'blocked';reason?:string;title?:string;lead?:string;context?:string;body?:string[];attention?:{title:string;text:string}[];sourceUrls?:string[];evidence:{url:string;status:string;origin?:string;readAt?:string;hash?:string;characters?:number;suppliedCharacters?:number;message?:string}[]}
export interface WeeklyEditorial {status:'not_generated'|'running'|'ready'|'partial'|'error'|'stale'|'interrupted';available:boolean;active?:boolean;completed?:number;total?:number;message?:string;articles?:WeeklyEditorialArticle[];sections?:{executive:{priority:string;overview:string};ransomware:{overview:string;trend:string;groups:string};ai:{interpretation:string;leadership:string};cves:{id:string;description:string;action:string}[]}}
export interface WeeklyCve {editorialFamily?:string|null;publicationSources?:number;id:string;description:string;vendor:string;product:string;cvss:number|null;severity:string;published:string;dateAdded:string;kev:boolean;epss:number|null;action:string;references:{url:string}[]}
interface PublicationMetadata {dateInferred?:boolean;publicationTimeKnown?:boolean;publicationDateBasis?:string;firstCollectedAt?:string;repository?:{dateBasis?:string}}
export interface WeeklyNews extends PublicationMetadata {id:string;title:string;summary:string;published:string;score:number;severity:string;sources:({title:string;source:string;link:string;published:string}&PublicationMetadata)[];categories:string[];actors:string[];malware:string[];cves:string[];ttps:string[]}
export interface WeeklyVictim {id:string;name:string;group:string;country:string;sector:string;published:string;discovered:string;permalink:string;description:string;claimStatus:'unconfirmed'}
export interface WeeklyReportData {
  editorial?:WeeklyEditorial;
  range:{id:string;from:string;to:string;timezone:string;exclusiveEnd:boolean};profile:{id:string;name:string;ransomwareSectors?:string[]}|null;generatedAt:string;updatedAt:string;revision:number;
  news:WeeklyNews[];aiNews:WeeklyNews[];
  candidates:{news:WeeklyNews[];aiNews:WeeklyNews[]};
  selection:{mode:'suggested'|'manual';newsIds:string[];aiNewsIds:string[]};
  vulnerabilities:{total:number;kevCount:number;critical:number;kev:WeeklyCve[];priority:WeeklyCve[];monitored:WeeklyCve[];editorial?:{focus:string[];highlights:WeeklyCve[];exploited:WeeklyCve[];missingFocus:string[]};ai:{total:number;critical:number;kevCount?:number;items:WeeklyCve[];vendors:{name:string;count:number}[];categories?:{name:string;count:number}[];previousTotal?:number|null;tools?:{name:string;count:number;cvss:number|null;id:string}[]}};
  ransomware:{total:number;latam:number;brazil:number;victims:WeeklyVictim[];byCountry:{name:string;count:number}[];byGroup:{name:string;count:number}[];bySector:{name:string;count:number}[];claimsAreUnconfirmed:boolean;focusSectors?:string[];focusCount?:number;focusBySector?:{name:string;count:number}[];history?:{from:string;to:string;available:boolean;latam:number|null;brazil:number|null;byGroup:{name:string;count:number}[]}[]};
  reports:{id:string;title:string;type:string;updatedAt:string;sources:string[]}[];
  recommendations:{priority:string;action:string;source:string;cve:string}[];
  actors:{name:string;count:number}[];malware:{name:string;count:number}[];ttps:{name:string;count:number}[];
  coverage:{news:{publications:number;lastCollectedAt:string|null};ransomware:{status:string;checkedAt?:string;message?:string};vulnerabilities:{status?:string;message?:string;sources?:Record<string,{status:string;at?:string}>}};
  sources:({title:string;source:string;link:string;published:string}&PublicationMetadata)[];
}
