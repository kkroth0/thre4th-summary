export interface WeeklyCve {id:string;description:string;vendor:string;product:string;cvss:number|null;severity:string;published:string;dateAdded:string;kev:boolean;epss:number|null;action:string;references:{url:string}[]}
interface PublicationMetadata {dateInferred?:boolean;publicationTimeKnown?:boolean;publicationDateBasis?:string;firstCollectedAt?:string;repository?:{dateBasis?:string}}
export interface WeeklyNews extends PublicationMetadata {id:string;title:string;summary:string;published:string;score:number;severity:string;sources:({title:string;source:string;link:string;published:string}&PublicationMetadata)[];categories:string[];actors:string[];malware:string[];cves:string[];ttps:string[]}
export interface WeeklyVictim {id:string;name:string;group:string;country:string;sector:string;published:string;discovered:string;permalink:string;description:string;claimStatus:'unconfirmed'}
export interface WeeklyReportData {
  range:{id:string;from:string;to:string;timezone:string;exclusiveEnd:boolean};profile:{id:string;name:string}|null;generatedAt:string;updatedAt:string;revision:number;
  news:WeeklyNews[];aiNews:WeeklyNews[];
  candidates:{news:WeeklyNews[];aiNews:WeeklyNews[]};
  selection:{mode:'suggested'|'manual';newsIds:string[];aiNewsIds:string[]};
  vulnerabilities:{total:number;kevCount:number;critical:number;kev:WeeklyCve[];priority:WeeklyCve[];monitored:WeeklyCve[];ai:{total:number;critical:number;items:WeeklyCve[];vendors:{name:string;count:number}[]}};
  ransomware:{total:number;latam:number;brazil:number;victims:WeeklyVictim[];byCountry:{name:string;count:number}[];byGroup:{name:string;count:number}[];bySector:{name:string;count:number}[];claimsAreUnconfirmed:boolean};
  reports:{id:string;title:string;type:string;updatedAt:string;sources:string[]}[];
  recommendations:{priority:string;action:string;source:string;cve:string}[];
  actors:{name:string;count:number}[];malware:{name:string;count:number}[];ttps:{name:string;count:number}[];
  coverage:{news:{publications:number;lastCollectedAt:string|null};ransomware:{status:string;checkedAt?:string;message?:string};vulnerabilities:{status?:string;message?:string;sources?:Record<string,{status:string;at?:string}>}};
  sources:({title:string;source:string;link:string;published:string}&PublicationMetadata)[];
}
