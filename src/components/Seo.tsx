import { useEffect } from "react";
import { useLocation } from "react-router-dom";
import { getSeoMetadata } from "@/config/seo";
import { useLanguage } from "@/contexts/LanguageContext";

const upsertMeta = (selector: string, attributes: Record<string, string>) => {
  let element = document.head.querySelector<HTMLMetaElement>(selector);
  if (!element) {
    element = document.createElement("meta");
    document.head.appendChild(element);
  }

  for (const [name, value] of Object.entries(attributes)) {
    element.setAttribute(name, value);
  }
};

const upsertLink = (selector: string, attributes: Record<string, string>) => {
  let element = document.head.querySelector<HTMLLinkElement>(selector);
  if (!element) {
    element = document.createElement("link");
    document.head.appendChild(element);
  }

  for (const [name, value] of Object.entries(attributes)) {
    element.setAttribute(name, value);
  }
};

export function Seo() {
  const location = useLocation();
  const { language } = useLanguage();

  useEffect(() => {
    const metadata = getSeoMetadata(location.pathname, language);

    document.documentElement.lang = metadata.htmlLang;
    document.title = metadata.title;

    upsertMeta('meta[name="description"]', { name: "description", content: metadata.description });
    upsertMeta('meta[name="language"]', { name: "language", content: metadata.htmlLang });
    upsertMeta('meta[property="og:title"]', { property: "og:title", content: metadata.title });
    upsertMeta('meta[property="og:description"]', { property: "og:description", content: metadata.description });
    upsertMeta('meta[property="og:type"]', { property: "og:type", content: "website" });
    upsertMeta('meta[property="og:url"]', { property: "og:url", content: metadata.canonicalUrl });
    upsertMeta('meta[property="og:image"]', { property: "og:image", content: metadata.imageUrl });
    upsertMeta('meta[property="og:locale"]', { property: "og:locale", content: metadata.locale });
    upsertMeta('meta[name="twitter:card"]', { name: "twitter:card", content: "summary_large_image" });
    upsertMeta('meta[name="twitter:title"]', { name: "twitter:title", content: metadata.title });
    upsertMeta('meta[name="twitter:description"]', { name: "twitter:description", content: metadata.description });
    upsertMeta('meta[name="twitter:image"]', { name: "twitter:image", content: metadata.imageUrl });

    upsertLink('link[rel="canonical"]', { rel: "canonical", href: metadata.canonicalUrl });
  }, [language, location.pathname]);

  return null;
}
