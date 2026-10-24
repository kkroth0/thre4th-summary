import manifest from '@/config/weeklyReportTemplate.json';

const escapePattern = (value: string) => value.replace(/[.*+?^$(){}|[\]\\]/g, '\\$&');
export const publisherNamePatterns = manifest.publisher.restrictedNames.map(name =>
  new RegExp('\\b' + name.split(/\s+/).map(escapePattern).join('\\s*') + '\\b', 'i'));
