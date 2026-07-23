// Thin adapter: keeps the object API `toast({ title, description, variant })`
// that ~30 call sites already use, but renders through sonner (the single toast
// system mounted in App.tsx). Replaces the old radix-toast reducer/machinery.
import type { ReactNode } from "react";
import { toast as sonnerToast } from "sonner";

type ToastInput = {
  title?: ReactNode;
  description?: ReactNode;
  variant?: "default" | "destructive" | null;
};

// title is the main line; when only `description` is passed (a few callers do),
// it becomes the main line. variant "destructive" maps to sonner's error style.
function toast({ title, description, variant }: ToastInput = {}) {
  const message = title ?? description ?? "";
  const options = title != null && description != null ? { description } : undefined;
  return variant === "destructive"
    ? sonnerToast.error(message, options)
    : sonnerToast(message, options);
}

function useToast() {
  return { toast };
}

export { useToast, toast };
