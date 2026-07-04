import React, { createContext, useContext, useState, useEffect } from 'react';
import { translations, Language, TranslationKey } from '../utils/translations';

const SUPPORTED: Language[] = ['pt', 'en', 'es', 'fr'];

interface LanguageContextType {
    language: Language;
    setLanguage: (lang: Language) => void;
    t: (key: TranslationKey, params?: Record<string, string | number>) => string;
    // Escolhe a variante do idioma atual para strings inline (não-dicionário).
    // Fallback: idioma atual -> inglês -> português -> primeira disponível.
    tr: (variants: Partial<Record<Language, string>>) => string;
}

const LanguageContext = createContext<LanguageContextType | undefined>(undefined);

export const LanguageProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
    // PT-BR é o idioma padrão; traduzível para en/es/fr.
    const [language, setLanguage] = useState<Language>('pt');

    useEffect(() => {
        const savedLang = localStorage.getItem('language') as Language;
        if (savedLang && SUPPORTED.includes(savedLang)) {
            setLanguage(savedLang);
        }
    }, []);

    const handleSetLanguage = (lang: Language) => {
        setLanguage(lang);
        localStorage.setItem('language', lang);
    };

    const t = (key: TranslationKey, params?: Record<string, string | number>): string => {
        let text = translations[language][key] || translations['en'][key] || key;

        if (params) {
            Object.entries(params).forEach(([paramKey, paramValue]) => {
                text = text.replace(`{${paramKey}}`, String(paramValue));
            });
        }

        return text;
    };

    const tr = (variants: Partial<Record<Language, string>>): string => {
        return variants[language] ?? variants.en ?? variants.pt ?? Object.values(variants)[0] ?? '';
    };

    return (
        <LanguageContext.Provider value={{ language, setLanguage: handleSetLanguage, t, tr }}>
            {children}
        </LanguageContext.Provider>
    );
};

export const useLanguage = () => {
    const context = useContext(LanguageContext);
    if (context === undefined) {
        throw new Error('useLanguage must be used within a LanguageProvider');
    }
    return context;
};
