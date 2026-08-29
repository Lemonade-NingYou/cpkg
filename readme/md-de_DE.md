# cpkg – Ein leichtgewichtiger C-Paketmanager

<div align="center">
  <img src="../image/cpkg icon.jpg" alt="cpkg Icon" width="200">
  
  ![Lizenz](https://img.shields.io/badge/license-GPLv3-blue.svg)
  ![Plattform](https://img.shields.io/badge/platform-Linux-green.svg)
  ![Version](https://img.shields.io/badge/version-2.0.0-brightgreen.svg)
  ![Status](https://img.shields.io/badge/status-stabil-brightgreen.svg)

**Ein leichtgewichtiger C-Paketmanager – einfach bauen und installieren**
</div>

## Sprache
[English](../README.md) | [中文](md-zh_CN.md) | Deutsch

## Einführung

cpkg ist ein leichtgewichtiger C-Paketmanager, der das Paketieren, Installieren und Verwalten von C-Bibliotheken und Kopfdateien vereinfacht.

Dieses Repository enthält eine **vollständig überarbeitete** Version von cpkg mit modularer Architektur, Integritätsprüfung (SHA‑256) und inkrementellen Builds.

Die Unterbefehle **build** und **install** sind voll funktionsfähig. Die Deinstallation ist für die nächste Version geplant.

## Funktionen

- **Build** – Erstellt aus einem Quellverzeichnis eine eigenständige `.cpl`-Datei.
- **Install** – Überprüft und installiert `.cpl`-Pakete in Systemverzeichnisse.
- **Integrität** – SHA‑256-Hash schützt vor Beschädigung oder Manipulation.
- **Inkrementell** – Nur geänderte Dateien werden beim Bau kopiert (spart Zeit).
- **Sauber** – Löscht temporäre Dateien nach der Installation automatisch.
- **Manifest** – Speichert jede installierte Datei für spätere Deinstallation.

## Projektstatus

| Funktion       | Status                  |
|----------------|-------------------------|
| `build`        | ✅ Abgeschlossen        |
| `install`      | ✅ Abgeschlossen        |
| `remove`       | ❌ Nicht begonnen       |
| `list`         | ❌ Nicht begonnen       |

## Erste Schritte

### Abhängigkeiten

```bash
sudo apt install libyaml-dev libarchive-dev libssl-dev libcjson-dev
```

### cpkg aus dem Quellcode erstellen

```bash
git clone https://github.com/chenhao2345/cpkg.git
cd cpkg
mkdir build && cd build
cmake ..
make
sudo make install
```

## Konfiguration (`config.txt`)

Die Konfigurationsdatei verwendet YAML. Ein ausführliches Beispiel und alle Felder sind im [englischen README](../README.md) beschrieben.

## Verwendung

### Paket bauen

```bash
cpkg -b /pfad/zum/projekt
```

Erzeugt `<PocketName>-<version>.cpl`.

### Paket installieren

```bash
sudo cpkg -i paketname.cpl
```

Installiert Bibliotheken und Header in die Systemverzeichnisse und erstellt ein Manifest unter `/var/cache/cpkg/<PocketName>.json`.

Weitere Optionen:

```bash
cpkg -h   # Hilfe
cpkg -V   # Version
```

## Mitwirken

1. Fork des [cpkg GitHub-Repositorys](https://github.com/chenhao2345/cpkg).
2. Neuen Branch für Ihre Änderungen erstellen.
3. Änderungen vornehmen und testen.
4. Pull-Request an den Hauptzweig senden.

## Lizenz

cpkg ist unter der GPLv3-Lizenz lizenziert.