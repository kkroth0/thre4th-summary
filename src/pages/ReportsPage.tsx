import { lazy } from 'react';
import { useSearchParams } from 'react-router-dom';
const DailyBulletin=lazy(()=>import('./DailyBulletin'));
const WeeklyReport=lazy(()=>import('./WeeklyReport'));
export default function ReportsPage(){const [params]=useSearchParams();return params.get('view')==='weekly'?<WeeklyReport />:<DailyBulletin />;}
