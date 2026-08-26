# cpkg – Ein leichtgewichtiger C-Paketmanager

<div align="center">
  <img src="../image/cpkg icon.jpg" alt="cpkg Icon" width="200">
  
  ![Lizenz](https://img.shields.io/badge/license-GPLv3-blue.svg)
  ![Plattform](https://img.shields.io/badge/platform-Linux-green.svg)
  ![Version](https://img.shields.io/badge/version-1.0-orange.svg)
  ![Status](https://img.shields.io/badge/status-Refactoring-yellow.svg)

**Ein leichtgewichtiger C-Paketmanager – derzeit in einer großen Überarbeitung**
</div>

## Sprache
[English](../README.md) | [中文](md-zh_CN.md) | Deutsch

## Einführung

cpkg ist ein leichtgewichtiger C-Paketmanager, der die Installation, Aktualisierung und Entfernung von C-Bibliotheken und Kopfdateien vereinfachen soll.

Dieses Repository enthält eine **Low-Level-Überarbeitung** des ursprünglichen cpkg. Die Codebasis wurde neu organisiert, und die Build-Pipeline wird für bessere Modularität, Sicherheit und Leistung neu geschrieben.

Derzeit ist nur die **Paketerstellung (build)** vollständig implementiert. Das Installationssubsystem befindet sich in aktiver Entwicklung und ist noch nicht funktionsfähig.

## Funktionen und Ziele

- **Erstellen** eines Pakets aus einem Quellverzeichnis in eine `.cpl`-Datei (fertig)
- **Installieren** eines `.cpl`-Pakets in das System (in Arbeit)
- Einfache Kommandozeilenschnittstelle
- Plattformübergreifende Unterstützung (Linux, macOS, Windows – geplant)

## Projektstatus

| Funktion      | Status                  |
|---------------|-------------------------|
| `build`       | ✅ Abgeschlossen        |
| `install`     | 🚧 In Entwicklung       |
| `remove`      | ❌ Nicht begonnen       |
| `list`        | ❌ Nicht begonnen       |

## Erste Schritte

### cpkg aus dem Quellcode erstellen

```bash
git clone https://github.com/chenhao2345/cpkg.git
cd cpkg
mkdir build && cd build
cmake ..
make
sudo make install
```

### Verwendung

Derzeit ist nur der folgende Befehl vollständig unterstützt:

```bash
cpkg -b <Build-Verzeichnis>
```

Dieser liest die `config.txt` aus dem angegebenen Verzeichnis, packt die angegebenen Bibliotheken und Kopfdateien und erzeugt eine `.cpl`-Datei.

Der Installationsbefehl ist teilweise implementiert, aber **noch nicht funktionsfähig**:

```bash
cpkg -i <package.cpl>   # (noch nicht bereit)
```

Weitere Optionen:

```bash
cpkg -h                 # Hilfe anzeigen
cpkg -V                 # Version anzeigen
```

## Mitwirken

Wenn Sie zu cpkg beitragen möchten, gehen Sie wie folgt vor:

1. Forken Sie das [cpkg GitHub-Repository](https://github.com/chenhao2345/cpkg).
2. Erstellen Sie einen neuen Branch für Ihre Änderungen.
3. Nehmen Sie Ihre Änderungen vor.
4. Testen Sie Ihre Änderungen.
5. Erstellen Sie einen Pull-Request an den Hauptzweig des cpkg-Repositorys.

## Lizenz

cpkg ist unter der GPLv3-Lizenz lizenziert.