import { useRef, type ReactNode } from 'react';
import { useLanguage } from '@/contexts/LanguageContext';
import { Sheet, SheetContent, SheetTitle, SheetDescription } from '@/components/ui/sheet';

export function RecordDrawer({ open, onClose, title, description, children }: {
  open: boolean; onClose: () => void; title: string; description: string; children: ReactNode;
}) {
  const opener = useRef<HTMLElement | null>(null);
  const { language } = useLanguage();
  return <Sheet open={open} onOpenChange={value => { if (!value) onClose(); }}>
    <SheetContent closeLabel={language === 'pt' ? 'Fechar detalhes' : 'Close details'} onOpenAutoFocus={() => { opener.current = document.activeElement instanceof HTMLElement ? document.activeElement : null; }} onCloseAutoFocus={event => { event.preventDefault(); if (opener.current?.isConnected) opener.current.focus(); }} className="workbench flex w-full flex-col gap-0 overflow-y-auto bg-background p-0 sm:max-w-[640px]">
      <div className="border-b p-6 pr-12"><SheetDescription className="mb-2 text-[11px] font-medium uppercase tracking-wider">{description}</SheetDescription><SheetTitle className="break-words text-xl leading-snug">{title}</SheetTitle></div>
      <div className="space-y-6 p-6">{children}</div>
    </SheetContent>
  </Sheet>;
}
