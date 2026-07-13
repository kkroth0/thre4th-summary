import { cn } from "@/lib/utils";

type BrandMarkProps = {
  className?: string;
  decorative?: boolean;
  alt?: string;
};

export function BrandMark({
  className,
  decorative = true,
  alt = "Threatsumm4ry",
}: BrandMarkProps) {
  return (
    <img
      src="/threatsumm4ry-mark.svg"
      alt={decorative ? "" : alt}
      aria-hidden={decorative || undefined}
      width={256}
      height={256}
      draggable={false}
      className={cn("shrink-0 select-none", className)}
    />
  );
}
