package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/moshequantum/openpassport/internal/passport"
)

const Version = "1.0.0"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]

	switch cmd {
	case "version", "--version", "-v":
		fmt.Printf("openpassport CLI v%s (OpenPassport v1.0 standard)\n", Version)
		return

	case "passport":
		handlePassport(os.Args[2:])

	case "init", "lint", "build", "verify", "export":
		// Allow direct subcommands without requiring the "passport" prefix
		handlePassport(os.Args[1:])

	case "help", "--help", "-h":
		printUsage()

	default:
		fmt.Printf("Comando desconocido: %s\n\n", cmd)
		printUsage()
		os.Exit(1)
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
  export [dir]     Empaqueta un perfil de seguridad (.tar.gz) para producción
  version          Muestra la versión de openpassport CLI

Ejemplos:
  openpassport init ./docs/passport-context --name "MiProyectoOS" --originator "Fundador"
  openpassport build ./docs/passport-context --fix-crlf
  openpassport verify ./docs/passport-context
  openpassport export ./docs/passport-context --profile core-public --out bundle.tar.gz`)
}

func handlePassport(args []string) {
	if len(args) < 1 {
		fmt.Println("Error: Falta el subcomando de passport (init, lint, build, verify, export).")
		os.Exit(1)
	}

	sub := args[0]
	subArgs := args[1:]

	targetDir := "."
	if len(subArgs) > 0 && !isFlag(subArgs[0]) {
		targetDir = subArgs[0]
		subArgs = subArgs[1:]
	}

	absDir, err := filepath.Abs(targetDir)
	if err != nil {
		fmt.Printf("Error resolviendo ruta: %v\n", err)
		os.Exit(1)
	}

	switch sub {
	case "init":
		fs := flag.NewFlagSet("init", flag.ExitOnError)
		name := fs.String("name", "Nuevo Pasaporte", "Nombre canónico del pasaporte")
		originator := fs.String("originator", "Fundador", "Nombre del originador / titular")
		_ = fs.Parse(subArgs)

		fmt.Printf("🚀 Inicializando OpenPassport v1.0 en: %s\n", absDir)
		if err := passport.InitPassport(absDir, *name, *originator); err != nil {
			fmt.Printf("❌ Error al inicializar: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("✅ 7 Capas, .gitattributes y MASTER-PROMPT.md creados exitosamente.")

	case "lint":
		fmt.Printf("🔍 Auditando pasaporte en: %s\n", absDir)
		issues, err := passport.LintPassport(absDir)
		if err != nil {
			fmt.Printf("❌ Error durante linting: %v\n", err)
			os.Exit(1)
		}
		if len(issues) == 0 {
			fmt.Println("✅ [PASS] El directorio cumple estrictamente con el estándar OpenPassport v1.0.")
		} else {
			fmt.Printf("⚠️ Se detectaron %d problemas:\n", len(issues))
			for _, iss := range issues {
				fmt.Printf("  - %s\n", iss)
			}
			os.Exit(1)
		}

	case "build":
		fs := flag.NewFlagSet("build", flag.ExitOnError)
		name := fs.String("name", "Pasaporte de Contexto", "Nombre canónico del pasaporte")
		originator := fs.String("originator", "Originador", "Titular del contexto")
		fixCRLF := fs.Bool("fix-crlf", true, "Normaliza automáticamente CRLF a LF en archivos de texto")
		_ = fs.Parse(subArgs)

		fmt.Printf("⚙️ Compilando pasaporte en: %s\n", absDir)
		m, err := passport.BuildPassport(absDir, *name, *originator, *fixCRLF)
		if err != nil {
			fmt.Printf("❌ Error durante la compilación: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✅ [PASS] Compilación determinista completada.\n")
		fmt.Printf("🔒 Manifest Self-Hash: %s\n", m.Files[0].Sha256)
		fmt.Printf("📄 Archivos procesados: %d\n", len(m.Files))
		fmt.Println("📜 generation.receipt.json generado con éxito.")

	case "verify":
		fmt.Printf("🔒 Verificando integridad criptográfica en: %s\n", absDir)
		ok, errs, err := passport.VerifyPassport(absDir)
		if err != nil {
			fmt.Printf("❌ Error: %v\n", err)
			os.Exit(1)
		}
		if ok {
			fmt.Println("🎉 [100% PASS] Todos los archivos verificados con hashes SHA-256 e integridad LF determinista.")
		} else {
			fmt.Println("💥 Falló la verificación de integridad:")
			for _, e := range errs {
				fmt.Printf("  - %s\n", e)
			}
			os.Exit(1)
		}

	case "export":
		fs := flag.NewFlagSet("export", flag.ExitOnError)
		profile := fs.String("profile", "core-public", "ID del perfil a exportar (core-public, full)")
		out := fs.String("out", "passport-bundle.tar.gz", "Archivo de salida")
		_ = fs.Parse(subArgs)

		fmt.Printf("📦 Exportando perfil '%s' hacia '%s'...\n", *profile, *out)
		if err := passport.ExportProfile(absDir, *profile, *out); err != nil {
			fmt.Printf("❌ Error exportando: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✅ Paquete generado exitosamente en %s\n", *out)

	default:
		fmt.Printf("Subcomando no reconocido: %s\n", sub)
		os.Exit(1)
	}
}

func isFlag(s string) bool {
	return len(s) > 0 && s[0] == '-'
}
