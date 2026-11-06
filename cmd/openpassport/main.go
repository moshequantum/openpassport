package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/moshequantum/openpassport/internal/passport"
)

// Version is injected at build time via -ldflags "-X main.Version=..."
var Version = "dev"

var noEmoji = false

func formatMsg(emoji, text string) string {
	if noEmoji {
		return text
	}
	return emoji + " " + text
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(2)
	}

	cmd := os.Args[1]

	switch cmd {
	case "version", "--version", "-v":
		fmt.Printf("openpassport CLI v%s (OpenPassport v1.0 standard)\n", Version)
		return

	case "passport":
		handlePassport(os.Args[2:])

	case "init", "lint", "build", "verify", "export":
		handlePassport(os.Args[1:])

	case "help", "--help", "-h":
		printUsage()
		os.Exit(0)

	default:
		fmt.Fprintf(os.Stderr, "Comando desconocido: %s\n\n", cmd)
		printUsage()
		os.Exit(2)
	}
}

func printUsage() {
	fmt.Println(`openpassport — Plano de control y compilador determinista para OpenPassport v1.0

Uso:
  openpassport [comando] [argumentos]

Comandos disponibles:
  init [dir]       Inicializa las 7 capas, .gitattributes y MASTER-PROMPT.md
  lint [dir]       Audita el directorio (CRLF, capas ausentes, consistencia)
  build [dir]      Compila, calcula SHA-256, sella manifestSelfHash y emite receipt
  verify [dir]     Verificación criptográfica read-only de integridad
  export [dir]     Empaqueta un perfil de seguridad (.tar.gz) determinista
  version          Muestra la versión de openpassport CLI

Códigos de salida:
  0: Éxito / Verificación PASS
  1: Fallo de verificación, linting o integridad
  2: Error de sintaxis, parámetros o uso

Opciones generales:
  --no-emoji       Desactiva pictogramas y emojis en la salida estándar`)
}

func handlePassport(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Error: Falta el subcomando de passport (init, lint, build, verify, export).")
		os.Exit(2)
	}

	sub := args[0]
	subArgs := args[1:]

	// Check global --no-emoji flag
	var filteredArgs []string
	for _, a := range subArgs {
		if a == "--no-emoji" {
			noEmoji = true
		} else {
			filteredArgs = append(filteredArgs, a)
		}
	}
	subArgs = filteredArgs

	targetDir := "."
	if len(subArgs) > 0 && !isFlag(subArgs[0]) {
		targetDir = subArgs[0]
		subArgs = subArgs[1:]
	}

	absDir, err := filepath.Abs(targetDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error resolviendo ruta: %v\n", err)
		os.Exit(2)
	}

	switch sub {
	case "init":
		fs := flag.NewFlagSet("init", flag.ContinueOnError)
		name := fs.String("name", "Nuevo Pasaporte", "Nombre canónico del pasaporte")
		originator := fs.String("originator", "Fundador", "Nombre del originador / titular")
		if err := fs.Parse(subArgs); err != nil {
			os.Exit(2)
		}

		fmt.Println(formatMsg("🚀", fmt.Sprintf("Inicializando OpenPassport v1.0 en: %s", absDir)))
		if err := passport.InitPassport(absDir, *name, *originator); err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", formatMsg("❌", fmt.Sprintf("Error al inicializar: %v", err)))
			os.Exit(1)
		}
		fmt.Println(formatMsg("✅", "7 Capas, .gitattributes y MASTER-PROMPT.md creados exitosamente."))

	case "lint":
		fs := flag.NewFlagSet("lint", flag.ContinueOnError)
		jsonOut := fs.Bool("json", false, "Salida en formato JSON estructurado")
		if err := fs.Parse(subArgs); err != nil {
			os.Exit(2)
		}

		if !*jsonOut {
			fmt.Println(formatMsg("🔍", fmt.Sprintf("Auditando pasaporte en: %s", absDir)))
		}
		issues, err := passport.LintPassport(absDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", formatMsg("❌", fmt.Sprintf("Error durante linting: %v", err)))
			os.Exit(1)
		}

		if *jsonOut {
			res := map[string]interface{}{
				"valid":  len(issues) == 0,
				"issues": issues,
				"dir":    absDir,
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			_ = enc.Encode(res)
		} else {
			if len(issues) == 0 {
				fmt.Println(formatMsg("✅", "[PASS] El directorio cumple estrictamente con el estándar OpenPassport v1.0."))
			} else {
				fmt.Printf("%s\n", formatMsg("⚠️", fmt.Sprintf("Se detectaron %d problemas:", len(issues))))
				for _, iss := range issues {
					fmt.Printf("  - %s\n", iss)
				}
			}
		}

		if len(issues) > 0 {
			os.Exit(1)
		}

	case "build":
		fs := flag.NewFlagSet("build", flag.ContinueOnError)
		name := fs.String("name", "Pasaporte de Contexto", "Nombre canónico del pasaporte")
		originator := fs.String("originator", "Originador", "Titular del contexto")
		authority := fs.String("authority", "", "Autoridad técnica del contexto")
		asOf := fs.String("as-of", "", "Fecha canónica asOf (YYYY-MM-DD)")
		fixCRLF := fs.Bool("fix-crlf", false, "Normaliza automáticamente CRLF a LF (desactivado por defecto)")
		if err := fs.Parse(subArgs); err != nil {
			os.Exit(2)
		}

		fmt.Println(formatMsg("⚙️", fmt.Sprintf("Compilando pasaporte en: %s", absDir)))
		m, err := passport.BuildPassport(absDir, passport.BuildOptions{
			Name:               *name,
			Originator:         *originator,
			TechnicalAuthority: *authority,
			AsOf:               *asOf,
			AutoFixCRLF:        *fixCRLF,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", formatMsg("❌", fmt.Sprintf("Error durante la compilación: %v", err)))
			os.Exit(1)
		}
		fmt.Println(formatMsg("✅", "[PASS] Compilación determinista completada."))
		fmt.Println(formatMsg("🔒", fmt.Sprintf("Manifest Self-Hash: %s", m.Files[0].Sha256)))
		fmt.Println(formatMsg("📄", fmt.Sprintf("Archivos procesados: %d", len(m.Files))))
		fmt.Println(formatMsg("📜", "generation.receipt.json generado con éxito."))

	case "verify":
		fs := flag.NewFlagSet("verify", flag.ContinueOnError)
		jsonOut := fs.Bool("json", false, "Salida en formato JSON estructurado")
		if err := fs.Parse(subArgs); err != nil {
			os.Exit(2)
		}

		if !*jsonOut {
			fmt.Println(formatMsg("🔒", fmt.Sprintf("Verificando integridad criptográfica en: %s", absDir)))
		}
		ok, errs, err := passport.VerifyPassport(absDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", formatMsg("❌", fmt.Sprintf("Error: %v", err)))
			os.Exit(1)
		}

		if *jsonOut {
			res := map[string]interface{}{
				"valid":  ok,
				"errors": errs,
				"dir":    absDir,
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			_ = enc.Encode(res)
		} else {
			if ok {
				fmt.Println(formatMsg("🎉", "[100% PASS] Todos los archivos verificados con hashes SHA-256 e integridad LF determinista."))
			} else {
				fmt.Println(formatMsg("💥", "Falló la verificación de integridad:"))
				for _, e := range errs {
					fmt.Printf("  - %s\n", e)
				}
			}
		}

		if !ok {
			os.Exit(1)
		}

	case "export":
		fs := flag.NewFlagSet("export", flag.ContinueOnError)
		profile := fs.String("profile", "core-public", "ID del perfil a exportar (core-public, full)")
		out := fs.String("out", "passport-bundle.tar.gz", "Archivo de salida")
		if err := fs.Parse(subArgs); err != nil {
			os.Exit(2)
		}

		fmt.Println(formatMsg("📦", fmt.Sprintf("Exportando perfil '%s' hacia '%s'...", *profile, *out)))
		if err := passport.ExportProfile(absDir, *profile, *out); err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", formatMsg("❌", fmt.Sprintf("Error exportando: %v", err)))
			os.Exit(1)
		}
		fmt.Println(formatMsg("✅", fmt.Sprintf("Paquete generado exitosamente en %s", *out)))

	default:
		fmt.Fprintf(os.Stderr, "Subcomando no reconocido: %s\n", sub)
		os.Exit(2)
	}
}

func isFlag(s string) bool {
	return len(s) > 0 && s[0] == '-'
}
