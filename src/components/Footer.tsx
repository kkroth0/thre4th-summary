import { Github, Twitter, Instagram, Linkedin } from "lucide-react";

export function Footer() {
    return (
        <footer className="border-t bg-background mt-auto">
            <div className="container mx-auto px-4 py-6">
                <div className="flex flex-col md:flex-row items-center justify-between gap-4">
                    <div className="text-sm text-muted-foreground">
                        © {new Date().getFullYear()} ThreatSumm4ry - kkroth0.
                    </div>

                    <div className="flex items-center gap-4">
                        <a
                            href="https://github.com/kkroth0"
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-muted-foreground hover:text-foreground transition-colors"
                            aria-label="GitHub"
                        >
                            <Github className="h-5 w-5" />
                        </a>
                        <a
                            href="https://x.com/kkct00"
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-muted-foreground hover:text-foreground transition-colors"
                            aria-label="Twitter"
                        >
                            <Twitter className="h-5 w-5" />
                        </a>
                        <a
                            href="https://www.linkedin.com/in/matheuslima-andrade/"
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-muted-foreground hover:text-foreground transition-colors"
                            aria-label="Instagram"
                        >
                            <Linkedin className="h-5 w-5" />
                        </a>
                    </div>
                </div>
            </div>
        </footer>
    );
}
