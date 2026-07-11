import { useState } from "react";
import { Loader2, Save, Trash2, Eye, Pencil } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import {
    Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger, DialogFooter,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Markdown } from "@/components/Markdown";
import { useLanguage } from "@/contexts/LanguageContext";
import { createPost, updatePost, deletePost, type Post, type PostCard } from "@/services/threatApi";

// Editor de publicação (admin). Cria ou edita um post; abas Escrever/Prévia
// pro corpo Markdown. `post` presente => modo edição. Chama onSaved/onDeleted
// pra a página recarregar a lista.
export function PostEditor({
    post, initial, trigger, onSaved, onDeleted,
}: {
    post?: Post | PostCard;
    // Seed para o modo de criação (ex.: rascunho vindo do gerador de relatórios).
    // Ignorado quando `post` está presente (modo edição).
    initial?: { title?: string; summary?: string; body?: string; tags?: string[] };
    trigger: React.ReactNode;
    onSaved: (p: Post) => void;
    onDeleted?: (id: string) => void;
}) {
    const { language } = useLanguage();
    const pt = language === "pt";
    const editing = !!post;

    const [open, setOpen] = useState(false);
    const [title, setTitle] = useState(post?.title ?? initial?.title ?? "");
    const [summary, setSummary] = useState(post?.summary ?? initial?.summary ?? "");
    const [tags, setTags] = useState((post?.tags ?? initial?.tags ?? []).join(", "));
    const [body, setBody] = useState((post as Post | undefined)?.body ?? initial?.body ?? "");
    const [published, setPublished] = useState(post?.published ?? false);
    const [saving, setSaving] = useState(false);
    const [deleting, setDeleting] = useState(false);

    const onSave = async () => {
        if (!title.trim()) { toast.error(pt ? "Informe o título" : "Enter a title"); return; }
        setSaving(true);
        try {
            const input = {
                title: title.trim(),
                summary: summary.trim(),
                body,
                tags: tags.split(",").map((t) => t.trim()).filter(Boolean),
                published,
            };
            const saved = editing ? await updatePost(post!.id, input) : await createPost(input);
            toast.success(editing ? (pt ? "Publicação atualizada" : "Post updated") : (pt ? "Publicação criada" : "Post created"));
            setOpen(false);
            onSaved(saved);
        } catch (e) {
            toast.error(e instanceof Error ? e.message : (pt ? "Falha ao salvar" : "Failed to save"));
        } finally {
            setSaving(false);
        }
    };

    const onDelete = async () => {
        if (!editing) return;
        if (!window.confirm(pt ? `Excluir "${post!.title}"? Isso é permanente.` : `Delete "${post!.title}"? This is permanent.`)) return;
        setDeleting(true);
        try {
            await deletePost(post!.id);
            toast.success(pt ? "Publicação excluída" : "Post deleted");
            setOpen(false);
            onDeleted?.(post!.id);
        } catch (e) {
            toast.error(e instanceof Error ? e.message : (pt ? "Falha ao excluir" : "Failed to delete"));
        } finally {
            setDeleting(false);
        }
    };

    return (
        <Dialog open={open} onOpenChange={setOpen}>
            <DialogTrigger asChild>{trigger}</DialogTrigger>
            <DialogContent className="max-w-3xl">
                <DialogHeader>
                    <DialogTitle>
                        {editing ? (pt ? "Editar publicação" : "Edit post") : (pt ? "Nova publicação" : "New post")}
                    </DialogTitle>
                </DialogHeader>

                <div className="space-y-3">
                    <div className="space-y-1">
                        <Label htmlFor="post-title" className="text-xs">{pt ? "Título" : "Title"}</Label>
                        <Input id="post-title" value={title} onChange={(e) => setTitle(e.target.value)}
                            placeholder={pt ? "Ex.: Nova campanha do AgentTesla mira o setor financeiro" : "e.g. New AgentTesla campaign targets finance"} />
                    </div>
                    <div className="space-y-1">
                        <Label htmlFor="post-summary" className="text-xs">{pt ? "Resumo (aparece nos cards)" : "Summary (shown on cards)"}</Label>
                        <Textarea id="post-summary" value={summary} onChange={(e) => setSummary(e.target.value)}
                            rows={2} placeholder={pt ? "Uma ou duas frases sobre a publicação." : "One or two sentences about the post."} />
                    </div>
                    <div className="space-y-1">
                        <Label htmlFor="post-tags" className="text-xs">{pt ? "Tags (separadas por vírgula)" : "Tags (comma-separated)"}</Label>
                        <Input id="post-tags" value={tags} onChange={(e) => setTags(e.target.value)}
                            placeholder="malware, phishing, ransomware" />
                    </div>

                    <div className="space-y-1">
                        <Label className="text-xs">{pt ? "Conteúdo (Markdown)" : "Content (Markdown)"}</Label>
                        <Tabs defaultValue="write">
                            <TabsList className="h-8">
                                <TabsTrigger value="write" className="gap-1.5 text-xs"><Pencil className="h-3.5 w-3.5" /> {pt ? "Escrever" : "Write"}</TabsTrigger>
                                <TabsTrigger value="preview" className="gap-1.5 text-xs"><Eye className="h-3.5 w-3.5" /> {pt ? "Prévia" : "Preview"}</TabsTrigger>
                            </TabsList>
                            <TabsContent value="write">
                                <Textarea value={body} onChange={(e) => setBody(e.target.value)} rows={14}
                                    className="font-mono text-[13px] leading-relaxed"
                                    placeholder={pt ? "# Cabeçalho\n\nEscreva em Markdown. **negrito**, listas, `código`, [links](https://…), tabelas…" : "# Heading\n\nWrite in Markdown. **bold**, lists, `code`, [links](https://…), tables…"} />
                            </TabsContent>
                            <TabsContent value="preview">
                                <ScrollArea className="h-[336px] rounded-md border p-4">
                                    {body.trim()
                                        ? <Markdown>{body}</Markdown>
                                        : <p className="text-sm text-muted-foreground">{pt ? "Nada para pré-visualizar ainda." : "Nothing to preview yet."}</p>}
                                </ScrollArea>
                            </TabsContent>
                        </Tabs>
                    </div>

                    <div className="flex items-center gap-2 rounded-md border px-3 py-2">
                        <Switch id="post-pub" checked={published} onCheckedChange={setPublished} />
                        <Label htmlFor="post-pub" className="text-sm cursor-pointer">
                            {published
                                ? (pt ? "Publicado — visível para todos" : "Published — visible to everyone")
                                : (pt ? "Rascunho — só você vê" : "Draft — only you can see it")}
                        </Label>
                    </div>
                </div>

                <DialogFooter className="gap-2 sm:justify-between">
                    {editing && onDeleted ? (
                        <Button variant="ghost" size="sm" className="text-destructive gap-1.5" onClick={onDelete} disabled={deleting || saving}>
                            {deleting ? <Loader2 className="h-4 w-4 animate-spin" /> : <Trash2 className="h-4 w-4" />}
                            {pt ? "Excluir" : "Delete"}
                        </Button>
                    ) : <span />}
                    <Button className="gap-2" onClick={onSave} disabled={saving || deleting}>
                        {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
                        {published ? (pt ? "Salvar e publicar" : "Save & publish") : (pt ? "Salvar rascunho" : "Save draft")}
                    </Button>
                </DialogFooter>
            </DialogContent>
        </Dialog>
    );
}
