import { countByCategory, filterNewsletterAdvisories, groupAdvisoriesIntoStories, filterStoryCards,
  type NewsletterFilterItem, type NewsletterFilterOptions, type StorySource } from '../pages/newsletterView';
import { annotateOrg, type OrgThreatModel } from './orgRelevance';

export type ProjectionItem = NewsletterFilterItem & StorySource;
export interface NewsProjectionOptions {
  filters: NewsletterFilterOptions;
  model: OrgThreatModel | null;
  category: string;
  orgOnly: boolean;
  pt: boolean;
}
// Keep the exact grouping/filtering rules shared with the table. Category
// counts and visible cards reuse one grouping instead of rebuilding it twice.
export function projectNews<T extends ProjectionItem>(items: T[], options: NewsProjectionOptions) {
  const filtered = annotateOrg(filterNewsletterAdvisories(items, options.filters), options.model);
  const grouped = groupAdvisoriesIntoStories(filtered, { sortByRelevance: options.filters.sortByRelevance, pt: options.pt });
  return { cards: filterStoryCards(grouped, { category: options.category, orgOnly: options.orgOnly && Boolean(options.model) }),
    counts: countByCategory(grouped) };
}

export function createNewsProjector<T extends ProjectionItem>() {
  let previous: T[] | undefined, modelKey: string | undefined;
  let annotated: (T & { orgScore: number })[] = [];
  return (items: T[], options: NewsProjectionOptions) => {
    const key = JSON.stringify(options.model);
    if (previous !== items || modelKey !== key) {
      annotated = annotateOrg(items, options.model); previous = items; modelKey = key;
    }
    const grouped = groupAdvisoriesIntoStories(filterNewsletterAdvisories(annotated, options.filters),
      { sortByRelevance: options.filters.sortByRelevance, pt: options.pt });
    return { cards: filterStoryCards(grouped, { category: options.category, orgOnly: options.orgOnly && Boolean(options.model) }), counts: countByCategory(grouped) };
  };
}
