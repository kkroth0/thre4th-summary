import { Github, Twitter, Linkedin } from "lucide-react";

export function Footer() {
    return (
        <footer className="relative z-10 mt-auto border-t border-primary/10 bg-background/80 backdrop-blur-xl">
            <div className="container mx-auto px-4 py-6">
                <div className="flex flex-col md:flex-row items-center justify-between gap-4">
                    <div className="text-sm text-muted-foreground">
                        © {new Date().getFullYear()} ThreatSumm4ry · Open source CTI · AGPL-3.0.
                    </div>

                    <div className="flex items-center gap-4">
                        <a
                            href="https://github.com/kkroth0/thre4th-summary"
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
                            aria-label="LinkedIn"
                        >
                            <Linkedin className="h-5 w-5" />
                        </a>
                    </div>
                </div>
            </div>
        </footer>
    );
}
